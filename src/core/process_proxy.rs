use crate::core::auth::{AuthenticatedOwner, ServiceError};
use crate::core::desired::ActiveOwnerState;
use crate::core::paths::service_paths;
use crate::{
    PROCESS_PROXY_MAX_TARGETS, ProcessProxyAttachRequest, ProcessProxySession, ProcessProxySessionStatus,
    ProcessProxyTarget, ProcessProxyUpdateRequest,
};
use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};
#[cfg(windows)]
use std::time::Duration;

#[cfg(windows)]
mod relay_listener;
#[cfg(windows)]
mod wfp;

const DRIVER_PROTOCOL_VERSION: u32 = 4;
static RECOVERY_REQUIRED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RecoveryPhase {
    #[default]
    Active,
    Pending,
}

#[derive(Deserialize, Serialize)]
struct RecoveryRecord {
    #[serde(default)]
    phase: RecoveryPhase,
    #[serde(flatten)]
    session: ProcessProxySession,
}

fn operation_lock() -> &'static tokio::sync::Mutex<()> {
    static LOCK: OnceLock<tokio::sync::Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| tokio::sync::Mutex::new(()))
}

/// Attaches the current active core session to the WFP control component.
///
/// A pending recovery record is durable before the driver can accept the session.
pub async fn attach_process_proxy(
    owner: &AuthenticatedOwner,
    active: &ActiveOwnerState,
    request: &ProcessProxyAttachRequest,
) -> std::result::Result<ProcessProxySessionStatus, ServiceError> {
    let _operation = operation_lock().lock().await;
    if RECOVERY_REQUIRED.load(Ordering::Acquire) {
        return Err(ServiceError::process_proxy_recovery_required(
            "a previous process-proxy operation requires recovery",
        ));
    }
    validate_request(request)?;
    match load_record().await {
        Ok(Some(_)) => {
            return Err(ServiceError::process_proxy_recovery_required(
                "a previous process-proxy session must be reconciled before attaching",
            ));
        }
        Ok(None) => {}
        Err(error) => {
            return Err(ServiceError::process_proxy_recovery_required(format!(
                "the process-proxy recovery record cannot be read safely: {error:#}"
            )));
        }
    }
    #[cfg(windows)]
    relay_listener::verify(request.relay_pid, request.relay_port)?;

    let session = ProcessProxySession {
        owner_key: owner.key.clone(),
        session_id: active.generation,
        relay_pid: request.relay_pid,
        relay_port: request.relay_port,
        targets: request.targets.clone(),
    };
    persist_record(&RecoveryRecord {
        phase: RecoveryPhase::Pending,
        session: session.clone(),
    })
    .await
    .map_err(|error| {
        RECOVERY_REQUIRED.store(true, Ordering::Release);
        ServiceError::process_proxy_recovery_required(format!(
            "the process-proxy recovery intent could not be persisted: {error:#}"
        ))
    })?;
    if let Err(error) = driver_attach(&session).await {
        return Err(rollback_failed_attach(session.session_id, error).await);
    }
    if let Err(error) = policy_install().await {
        return Err(rollback_failed_attach(session.session_id, error).await);
    }
    if !driver_session_matches(&session).await.unwrap_or(false) {
        return Err(rollback_failed_attach(
            session.session_id,
            ServiceError::process_proxy_recovery_required("the driver did not retain the attached exact targets"),
        )
        .await);
    }
    if let Err(error) = persist_record(&RecoveryRecord {
        phase: RecoveryPhase::Active,
        session: session.clone(),
    })
    .await
    {
        return Err(rollback_failed_attach(
            session.session_id,
            ServiceError::process_proxy_recovery_required(format!(
                "the accepted driver session could not be marked active: {error:#}"
            )),
        )
        .await);
    }
    #[cfg(windows)]
    tokio::spawn(monitor_session(session.owner_key.clone(), session.session_id));
    Ok(ProcessProxySessionStatus::Active { session })
}

/// Replaces the selected exact instances without removing the active WFP filters.
pub async fn update_process_proxy_targets(
    owner: &AuthenticatedOwner,
    active: &ActiveOwnerState,
    request: &ProcessProxyUpdateRequest,
) -> std::result::Result<ProcessProxySessionStatus, ServiceError> {
    let _operation = operation_lock().lock().await;
    if RECOVERY_REQUIRED.load(Ordering::Acquire) {
        return Err(ServiceError::process_proxy_recovery_required(
            "a previous process-proxy operation requires recovery",
        ));
    }
    let Some(record) = load_record().await.map_err(recovery_read_error)? else {
        return Err(ServiceError::invalid_process_proxy_session(
            "no process-proxy session is attached",
        ));
    };
    if record.phase != RecoveryPhase::Active
        || record.session.owner_key != owner.key
        || record.session.session_id != active.generation
    {
        return Err(ServiceError::process_proxy_recovery_required(
            "the recorded process-proxy session is not active for this owner",
        ));
    }
    validate_targets(&request.targets, record.session.relay_pid)?;
    #[cfg(windows)]
    if let Err(error) = relay_listener::verify(record.session.relay_pid, record.session.relay_port) {
        return Err(rollback_failed_update(record.session.session_id, error).await);
    }
    if !policy_is_active().await {
        return Err(rollback_failed_update(
            record.session.session_id,
            ServiceError::process_proxy_recovery_required("the WFP redirect filters are unavailable"),
        )
        .await);
    }
    let mut session = record.session;
    session.targets = request.targets.clone();
    if let Err(error) = driver_update(&session).await {
        return Err(rollback_failed_update(session.session_id, error).await);
    }
    if !driver_session_matches(&session).await.unwrap_or(false) {
        return Err(rollback_failed_update(
            session.session_id,
            ServiceError::process_proxy_recovery_required("the driver did not retain the updated exact targets"),
        )
        .await);
    }
    if let Err(error) = persist_record(&RecoveryRecord {
        phase: RecoveryPhase::Active,
        session: session.clone(),
    })
    .await
    {
        return Err(rollback_failed_update(
            session.session_id,
            ServiceError::process_proxy_recovery_required(format!(
                "the updated target set could not be persisted: {error:#}"
            )),
        )
        .await);
    }
    Ok(ProcessProxySessionStatus::Active { session })
}

async fn rollback_failed_update(session_id: u64, error: ServiceError) -> ServiceError {
    match clear_recorded_session(session_id).await {
        Ok(()) => error,
        Err(cleanup_error) => {
            RECOVERY_REQUIRED.store(true, Ordering::Release);
            ServiceError::process_proxy_recovery_required(format!(
                "process-proxy target update failed: {error}; session cleanup failed: {cleanup_error:#}"
            ))
        }
    }
}

async fn rollback_failed_attach(session_id: u64, error: ServiceError) -> ServiceError {
    if let Err(rollback_error) = policy_remove().await {
        RECOVERY_REQUIRED.store(true, Ordering::Release);
        return ServiceError::process_proxy_recovery_required(format!(
            "process-proxy attach failed: {error}; WFP policy rollback failed: {rollback_error}"
        ));
    }
    if let Err(rollback_error) = driver_detach(session_id).await {
        RECOVERY_REQUIRED.store(true, Ordering::Release);
        return ServiceError::process_proxy_recovery_required(format!(
            "process-proxy attach failed: {error}; driver rollback failed: {rollback_error}"
        ));
    }
    if let Err(clear_error) = clear_record().await {
        RECOVERY_REQUIRED.store(true, Ordering::Release);
        return ServiceError::process_proxy_recovery_required(format!(
            "process-proxy attach failed: {error}; recovery record could not be cleared: {clear_error:#}"
        ));
    }
    error
}

/// Detaches only the current authenticated owner's recorded session.
pub async fn detach_process_proxy(
    owner: &AuthenticatedOwner,
    active: &ActiveOwnerState,
) -> std::result::Result<ProcessProxySessionStatus, ServiceError> {
    let _operation = operation_lock().lock().await;
    let Some(record) = load_record().await.map_err(recovery_read_error)? else {
        return Ok(ProcessProxySessionStatus::Idle);
    };
    let session = record.session;
    if session.owner_key != owner.key || session.session_id != active.generation {
        return Err(ServiceError::process_proxy_recovery_required(
            "the recorded process-proxy session does not belong to the active owner session",
        ));
    }
    policy_remove().await.inspect_err(|_| {
        RECOVERY_REQUIRED.store(true, Ordering::Release);
    })?;
    driver_detach(session.session_id).await.inspect_err(|_| {
        RECOVERY_REQUIRED.store(true, Ordering::Release);
    })?;
    clear_record().await.map_err(|error| {
        RECOVERY_REQUIRED.store(true, Ordering::Release);
        ServiceError::process_proxy_recovery_required(format!(
            "the driver session was detached but its recovery record could not be cleared: {error:#}"
        ))
    })?;
    RECOVERY_REQUIRED.store(false, Ordering::Release);
    Ok(ProcessProxySessionStatus::Idle)
}

/// Returns a fail-closed status without exposing another owner's target list.
pub async fn process_proxy_status(owner: &AuthenticatedOwner, active: &ActiveOwnerState) -> ProcessProxySessionStatus {
    let _operation = operation_lock().lock().await;
    if RECOVERY_REQUIRED.load(Ordering::Acquire) {
        return ProcessProxySessionStatus::RecoveryRequired {
            detail: "a previous process-proxy operation requires recovery".to_owned(),
        };
    }
    match load_record().await {
        Ok(None) => ProcessProxySessionStatus::Idle,
        Ok(Some(record)) if record.session.owner_key == owner.key && record.session.session_id == active.generation => {
            match record.phase {
                RecoveryPhase::Active => {
                    let targets_live = active_target_present(&record.session).await;
                    if matches!(targets_live, Ok(false)) {
                        match clear_recorded_session(record.session.session_id).await {
                            Ok(()) => ProcessProxySessionStatus::Idle,
                            Err(error) => ProcessProxySessionStatus::RecoveryRequired {
                                detail: format!("failed to detach exited process-proxy targets: {error:#}"),
                            },
                        }
                    } else if targets_live.is_err() {
                        ProcessProxySessionStatus::RecoveryRequired {
                            detail: "the selected process identities cannot be verified".to_owned(),
                        }
                    } else if !policy_is_active().await {
                        ProcessProxySessionStatus::RecoveryRequired {
                            detail: "the WFP redirect filters are unavailable".to_owned(),
                        }
                    } else if !driver_session_matches(&record.session).await.unwrap_or(false) {
                        ProcessProxySessionStatus::RecoveryRequired {
                            detail: "the driver session is unavailable or differs from the recorded exact targets"
                                .to_owned(),
                        }
                    } else if !relay_listeners_present(&record.session) {
                        ProcessProxySessionStatus::RecoveryRequired {
                            detail: "the process-proxy relay listeners are unavailable".to_owned(),
                        }
                    } else {
                        ProcessProxySessionStatus::Active {
                            session: record.session,
                        }
                    }
                }
                RecoveryPhase::Pending => ProcessProxySessionStatus::RecoveryRequired {
                    detail: "a process-proxy attach was interrupted before activation".to_owned(),
                },
            }
        }
        Ok(Some(_)) => ProcessProxySessionStatus::RecoveryRequired {
            detail: "a process-proxy recovery record belongs to a different owner session".to_owned(),
        },
        Err(error) => ProcessProxySessionStatus::RecoveryRequired {
            detail: format!("the process-proxy recovery record cannot be read safely: {error:#}"),
        },
    }
}

#[cfg(windows)]
fn relay_listeners_present(session: &ProcessProxySession) -> bool {
    relay_listener::verify(session.relay_pid, session.relay_port).is_ok()
}

#[cfg(not(windows))]
fn relay_listeners_present(_session: &ProcessProxySession) -> bool {
    false
}

#[cfg(windows)]
async fn active_target_present(session: &ProcessProxySession) -> Result<bool> {
    let targets = session.targets.clone();
    tokio::task::spawn_blocking(move || {
        for target in targets {
            if crate::core::process::process_identity(target.pid)?
                .is_some_and(|identity| identity.started_at == target.created_at)
            {
                return Ok(true);
            }
        }
        Ok(false)
    })
    .await?
}

#[cfg(not(windows))]
async fn active_target_present(_session: &ProcessProxySession) -> Result<bool> {
    Ok(true)
}

#[cfg(windows)]
async fn driver_session_matches(session: &ProcessProxySession) -> std::result::Result<bool, ServiceError> {
    let session = session.clone();
    tokio::task::spawn_blocking(move || {
        let snapshot = driver_query_blocking()?;
        if snapshot.session_id != session.session_id
            || snapshot.relay_pid != session.relay_pid
            || snapshot.relay_port != session.relay_port
        {
            return Ok(false);
        }
        let recorded: std::collections::BTreeSet<_> = session
            .targets
            .iter()
            .map(|target| (target.pid, target.created_at))
            .collect();
        let mut observed = std::collections::BTreeSet::new();
        for target in snapshot.targets.iter().take(snapshot.target_count as usize) {
            if target.pid == 0 && target.created_at == 0 {
                continue;
            }
            let Ok(pid) = u32::try_from(target.pid) else {
                return Ok(false);
            };
            if !recorded.contains(&(pid, target.created_at)) || !observed.insert((pid, target.created_at)) {
                return Ok(false);
            }
        }
        for target in &session.targets {
            let live = crate::core::process::process_identity(target.pid)
                .map_err(|error| {
                    ServiceError::process_proxy_recovery_required(format!(
                        "the selected process identity cannot be verified: {error:#}"
                    ))
                })?
                .is_some_and(|identity| identity.started_at == target.created_at);
            if live && !observed.contains(&(target.pid, target.created_at)) {
                return Ok(false);
            }
        }
        Ok(true)
    })
    .await
    .map_err(|error| ServiceError::process_proxy_unavailable(format!("driver status worker failed: {error}")))?
}

#[cfg(not(windows))]
async fn driver_session_matches(_session: &ProcessProxySession) -> std::result::Result<bool, ServiceError> {
    Err(ServiceError::process_proxy_unavailable(
        "process proxy is only available in the Windows service",
    ))
}

#[cfg(windows)]
async fn monitor_session(owner_key: String, session_id: u64) {
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    loop {
        interval.tick().await;
        let _operation = operation_lock().lock().await;
        let record = match load_record().await {
            Ok(Some(record)) => record,
            Ok(None) => return,
            Err(error) => {
                RECOVERY_REQUIRED.store(true, Ordering::Release);
                tracing::error!("process-proxy monitor cannot read its recovery record: {error:#}");
                return;
            }
        };
        if record.session.owner_key != owner_key || record.session.session_id != session_id {
            return;
        }
        if record.phase != RecoveryPhase::Active {
            RECOVERY_REQUIRED.store(true, Ordering::Release);
            tracing::error!("process-proxy monitor found a non-active recovery record");
            return;
        }
        let targets_live = active_target_present(&record.session).await;
        if matches!(targets_live, Ok(true))
            && policy_is_active().await
            && driver_session_matches(&record.session).await.unwrap_or(false)
            && relay_listeners_present(&record.session)
        {
            continue;
        }
        if let Err(error) = clear_recorded_session(session_id).await {
            RECOVERY_REQUIRED.store(true, Ordering::Release);
            tracing::error!("process-proxy monitor could not detach its session: {error:#}");
        }
        return;
    }
}

/// Runs before restoring normal service work. A surviving record is never assumed idle:
/// the service first asks the driver to detach it, then removes the record.
pub async fn reconcile_process_proxy_session() -> Result<()> {
    let _operation = operation_lock().lock().await;
    let Some(record) = load_record().await? else {
        return Ok(());
    };
    clear_recorded_session(record.session.session_id).await
}

async fn clear_recorded_session(session_id: u64) -> Result<()> {
    policy_remove().await.map_err(|error| anyhow::anyhow!(error.message))?;
    driver_detach(session_id)
        .await
        .map_err(|error| anyhow::anyhow!(error.message))?;
    clear_record().await?;
    RECOVERY_REQUIRED.store(false, Ordering::Release);
    Ok(())
}

fn validate_request(request: &ProcessProxyAttachRequest) -> std::result::Result<(), ServiceError> {
    if request.relay_pid == 0 || request.relay_port == 0 {
        return Err(ServiceError::invalid_process_proxy_session(
            "relay PID and loopback port are required",
        ));
    }
    validate_targets(&request.targets, request.relay_pid)
}

fn validate_targets(targets: &[ProcessProxyTarget], relay_pid: u32) -> std::result::Result<(), ServiceError> {
    if targets.is_empty() || targets.len() > PROCESS_PROXY_MAX_TARGETS {
        return Err(ServiceError::invalid_process_proxy_session(format!(
            "target count must be between 1 and {PROCESS_PROXY_MAX_TARGETS}"
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for target in targets {
        if target.pid == 0 || target.created_at == 0 {
            return Err(ServiceError::invalid_process_proxy_session(
                "each target requires a PID and creation timestamp",
            ));
        }
        if target.pid == relay_pid {
            return Err(ServiceError::invalid_process_proxy_session(
                "the relay process cannot be a redirected target",
            ));
        }
        if !seen.insert(target.pid) {
            return Err(ServiceError::invalid_process_proxy_session(
                "target PIDs must be unique",
            ));
        }
    }
    Ok(())
}

fn recovery_read_error(error: anyhow::Error) -> ServiceError {
    ServiceError::process_proxy_recovery_required(format!(
        "the process-proxy recovery record cannot be read safely: {error:#}"
    ))
}

#[cfg(windows)]
async fn policy_install() -> std::result::Result<(), ServiceError> {
    tokio::task::spawn_blocking(wfp::install)
        .await
        .map_err(|error| ServiceError::process_proxy_unavailable(format!("WFP policy worker failed: {error}")))?
}

#[cfg(not(windows))]
async fn policy_install() -> std::result::Result<(), ServiceError> {
    Err(ServiceError::process_proxy_unavailable(
        "WFP policy is only available on Windows",
    ))
}

#[cfg(windows)]
async fn policy_remove() -> std::result::Result<(), ServiceError> {
    tokio::task::spawn_blocking(wfp::remove)
        .await
        .map_err(|error| ServiceError::process_proxy_unavailable(format!("WFP policy worker failed: {error}")))?
}

#[cfg(not(windows))]
async fn policy_remove() -> std::result::Result<(), ServiceError> {
    Ok(())
}

#[cfg(windows)]
async fn policy_is_active() -> bool {
    tokio::task::spawn_blocking(wfp::is_active).await.unwrap_or(false)
}

#[cfg(not(windows))]
async fn policy_is_active() -> bool {
    true
}

async fn load_record() -> Result<Option<RecoveryRecord>> {
    let path = service_paths()?.process_proxy_session_path();
    crate::core::platform_security::secure_private_service_file_if_exists(&path)?;
    match tokio::fs::read(&path).await {
        Ok(content) => Ok(Some(
            serde_json::from_slice(&content).with_context(|| format!("failed to parse {path:?}"))?,
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("failed to read {path:?}")),
    }
}

async fn persist_record(record: &RecoveryRecord) -> Result<()> {
    let path = service_paths()?.process_proxy_session_path();
    crate::core::desired::write_json_atomic(&path, record).await
}

async fn clear_record() -> Result<()> {
    let path = service_paths()?.process_proxy_session_path();
    crate::core::platform_security::secure_private_service_file_if_exists(&path)?;
    match tokio::fs::remove_file(&path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("failed to remove {path:?}")),
    }
}

#[cfg(windows)]
async fn driver_attach(session: &ProcessProxySession) -> std::result::Result<(), ServiceError> {
    let session = session.clone();
    tokio::task::spawn_blocking(move || driver_attach_blocking(&session))
        .await
        .map_err(|error| ServiceError::process_proxy_unavailable(format!("driver attach worker failed: {error}")))?
}

#[cfg(not(windows))]
async fn driver_attach(_session: &ProcessProxySession) -> std::result::Result<(), ServiceError> {
    Err(ServiceError::process_proxy_unavailable(
        "process proxy is only available in the Windows service",
    ))
}

#[cfg(windows)]
async fn driver_update(session: &ProcessProxySession) -> std::result::Result<(), ServiceError> {
    let session = session.clone();
    tokio::task::spawn_blocking(move || driver_update_blocking(&session))
        .await
        .map_err(|error| ServiceError::process_proxy_unavailable(format!("driver update worker failed: {error}")))?
}

#[cfg(not(windows))]
async fn driver_update(_session: &ProcessProxySession) -> std::result::Result<(), ServiceError> {
    Err(ServiceError::process_proxy_unavailable(
        "process proxy is only available in the Windows service",
    ))
}

#[cfg(windows)]
async fn driver_detach(session_id: u64) -> std::result::Result<(), ServiceError> {
    tokio::task::spawn_blocking(move || driver_detach_blocking(session_id))
        .await
        .map_err(|error| ServiceError::process_proxy_unavailable(format!("driver detach worker failed: {error}")))?
}

#[cfg(not(windows))]
async fn driver_detach(_session_id: u64) -> std::result::Result<(), ServiceError> {
    Err(ServiceError::process_proxy_unavailable(
        "process proxy is only available in the Windows service",
    ))
}

#[cfg(windows)]
#[repr(C)]
#[derive(Clone, Copy)]
struct DriverTarget {
    pid: u64,
    created_at: u64,
}

#[cfg(windows)]
#[repr(C)]
struct DriverAttachRequest {
    version: u32,
    size: u32,
    session_id: u64,
    relay_pid: u32,
    relay_port: u16,
    target_count: u16,
    targets: [DriverTarget; PROCESS_PROXY_MAX_TARGETS],
}

#[cfg(windows)]
#[repr(C)]
struct DriverDetachRequest {
    version: u32,
    size: u32,
    session_id: u64,
}

#[cfg(windows)]
#[repr(C)]
struct DriverUpdateRequest {
    version: u32,
    size: u32,
    session_id: u64,
    target_count: u32,
    reserved: u32,
    targets: [DriverTarget; PROCESS_PROXY_MAX_TARGETS],
}

#[cfg(windows)]
#[repr(C)]
struct DriverQueryResponse {
    version: u32,
    size: u32,
    session_id: u64,
    relay_pid: u32,
    relay_port: u16,
    target_count: u16,
    targets: [DriverTarget; PROCESS_PROXY_MAX_TARGETS],
}

#[cfg(windows)]
const IOCTL_ATTACH_SESSION: u32 = 0x0012_a004;
#[cfg(windows)]
const IOCTL_DETACH_SESSION: u32 = 0x0012_a008;
#[cfg(windows)]
const IOCTL_UPDATE_TARGETS: u32 = 0x0012_a00c;
#[cfg(windows)]
const IOCTL_QUERY_SESSION: u32 = 0x0012_6010;

#[cfg(windows)]
fn driver_attach_blocking(session: &ProcessProxySession) -> std::result::Result<(), ServiceError> {
    let mut request = DriverAttachRequest {
        version: DRIVER_PROTOCOL_VERSION,
        size: std::mem::size_of::<DriverAttachRequest>() as u32,
        session_id: session.session_id,
        relay_pid: session.relay_pid,
        relay_port: session.relay_port,
        target_count: session.targets.len() as u16,
        targets: [DriverTarget { pid: 0, created_at: 0 }; PROCESS_PROXY_MAX_TARGETS],
    };
    for (index, target) in session.targets.iter().enumerate() {
        request.targets[index] = DriverTarget {
            pid: target.pid as u64,
            created_at: target.created_at,
        };
    }
    send_driver_ioctl(IOCTL_ATTACH_SESSION, &request)
}

#[cfg(windows)]
fn driver_update_blocking(session: &ProcessProxySession) -> std::result::Result<(), ServiceError> {
    let mut request = DriverUpdateRequest {
        version: DRIVER_PROTOCOL_VERSION,
        size: std::mem::size_of::<DriverUpdateRequest>() as u32,
        session_id: session.session_id,
        target_count: session.targets.len() as u32,
        reserved: 0,
        targets: [DriverTarget { pid: 0, created_at: 0 }; PROCESS_PROXY_MAX_TARGETS],
    };
    for (index, target) in session.targets.iter().enumerate() {
        request.targets[index] = DriverTarget {
            pid: target.pid as u64,
            created_at: target.created_at,
        };
    }
    send_driver_ioctl(IOCTL_UPDATE_TARGETS, &request)
}

#[cfg(windows)]
fn driver_detach_blocking(session_id: u64) -> std::result::Result<(), ServiceError> {
    let request = DriverDetachRequest {
        version: DRIVER_PROTOCOL_VERSION,
        size: std::mem::size_of::<DriverDetachRequest>() as u32,
        session_id,
    };
    send_driver_ioctl(IOCTL_DETACH_SESSION, &request)
}

#[cfg(windows)]
fn driver_query_blocking() -> std::result::Result<DriverQueryResponse, ServiceError> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GENERIC_READ, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
        System::IO::DeviceIoControl,
    };

    let path = r"\\.\Clash5ProcessProxy"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ServiceError::process_proxy_unavailable(format!(
            "the Clash5 WFP driver control device is unavailable: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut response = DriverQueryResponse {
        version: 0,
        size: 0,
        session_id: 0,
        relay_pid: 0,
        relay_port: 0,
        target_count: 0,
        targets: [DriverTarget { pid: 0, created_at: 0 }; PROCESS_PROXY_MAX_TARGETS],
    };
    let mut returned = 0_u32;
    let result = unsafe {
        DeviceIoControl(
            handle,
            IOCTL_QUERY_SESSION,
            std::ptr::null(),
            0,
            (&mut response as *mut DriverQueryResponse).cast(),
            std::mem::size_of::<DriverQueryResponse>() as u32,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        CloseHandle(handle);
    }
    if result == 0 {
        return Err(ServiceError::process_proxy_unavailable(format!(
            "the Clash5 WFP driver session cannot be read: {error}"
        )));
    }
    if returned as usize != std::mem::size_of::<DriverQueryResponse>()
        || response.version != DRIVER_PROTOCOL_VERSION
        || response.size as usize != std::mem::size_of::<DriverQueryResponse>()
        || response.session_id == 0
        || response.relay_pid == 0
        || response.relay_port == 0
        || response.target_count as usize > PROCESS_PROXY_MAX_TARGETS
    {
        return Err(ServiceError::process_proxy_recovery_required(
            "the Clash5 WFP driver returned an invalid session snapshot",
        ));
    }
    Ok(response)
}

#[cfg(windows)]
fn send_driver_ioctl<T>(code: u32, request: &T) -> std::result::Result<(), ServiceError> {
    use std::ffi::c_void;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GENERIC_WRITE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
        System::IO::DeviceIoControl,
    };

    let path = r"\\.\Clash5ProcessProxy"
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            path.as_ptr(),
            GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            std::ptr::null(),
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(ServiceError::process_proxy_unavailable(format!(
            "the Clash5 WFP driver control device is unavailable: {}",
            std::io::Error::last_os_error()
        )));
    }
    let mut returned = 0_u32;
    let result = unsafe {
        DeviceIoControl(
            handle,
            code,
            request as *const T as *const c_void,
            std::mem::size_of::<T>() as u32,
            std::ptr::null_mut(),
            0,
            &mut returned,
            std::ptr::null_mut(),
        )
    };
    let error = std::io::Error::last_os_error();
    unsafe {
        CloseHandle(handle);
    }
    if result == 0 {
        return Err(ServiceError::process_proxy_unavailable(format!(
            "the Clash5 WFP driver rejected the session request: {error}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{RecoveryPhase, RecoveryRecord, validate_request};
    use crate::{ProcessProxyAttachRequest, ProcessProxySession, ProcessProxySessionStatus, ProcessProxyTarget};

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an elevated Windows host with the clash5 WFP driver loaded"]
    fn exact_target_tcp_reaches_loopback_relay() {
        use super::{driver_attach_blocking, driver_detach_blocking, wfp};
        use crate::core::process::process_identity;
        use std::io::{ErrorKind, Read};
        use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};
        use std::os::windows::io::AsRawSocket;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};
        use windows_sys::Win32::Networking::WinSock::{
            AF_INET, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
            SOCKADDR_STORAGE, WSAGetLastError, WSAIoctl,
        };

        #[repr(C)]
        struct RedirectContext {
            version: u32,
            size: u32,
            session_id: u64,
            original_destination: SOCKADDR_STORAGE,
        }

        struct Cleanup {
            child: Child,
            session_id: u64,
            attached: bool,
            policy: bool,
        }

        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                if self.policy {
                    let _ = wfp::remove();
                }
                if self.attached {
                    let _ = driver_detach_blocking(self.session_id);
                }
            }
        }

        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let relay_port = listener.local_addr().unwrap().port();
        let _ipv6_listener = TcpListener::bind((Ipv6Addr::LOCALHOST, relay_port)).unwrap();
        let script = r#"Start-Sleep -Seconds 5; $client = New-Object System.Net.Sockets.TcpClient; try { $client.Connect('198.51.100.10', 443); $bytes = [Text.Encoding]::ASCII.GetBytes('C5!'); $client.GetStream().Write($bytes, 0, $bytes.Length) } finally { $client.Dispose() }"#;
        let child = Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let target = process_identity(child.id()).unwrap().unwrap();
        let session_id = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        )
        .unwrap();
        let session = ProcessProxySession {
            owner_key: "smoke".to_owned(),
            session_id,
            relay_pid: std::process::id(),
            relay_port,
            targets: vec![ProcessProxyTarget {
                pid: child.id(),
                created_at: target.started_at,
            }],
        };
        let mut cleanup = Cleanup {
            child,
            session_id,
            attached: false,
            policy: false,
        };
        driver_attach_blocking(&session).unwrap();
        cleanup.attached = true;
        wfp::install().unwrap();
        cleanup.policy = true;

        let deadline = Instant::now() + Duration::from_secs(20);
        let mut stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break stream,
                Err(error) if error.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(error) => panic!("redirected target did not reach relay: {error}"),
            }
        };
        stream.set_nonblocking(false).unwrap();
        stream.set_read_timeout(Some(Duration::from_secs(2))).unwrap();
        let socket = usize::try_from(stream.as_raw_socket()).unwrap();
        let mut context = RedirectContext {
            version: 0,
            size: 0,
            session_id: 0,
            original_destination: SOCKADDR_STORAGE::default(),
        };
        let mut context_bytes = 0;
        let result = unsafe {
            WSAIoctl(
                socket,
                SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
                std::ptr::null(),
                0,
                (&mut context as *mut RedirectContext).cast(),
                std::mem::size_of::<RedirectContext>() as u32,
                &mut context_bytes,
                std::ptr::null_mut(),
                None,
            )
        };
        assert_eq!(result, 0, "redirect context query failed: {}", unsafe {
            WSAGetLastError()
        });
        assert_eq!(context_bytes as usize, std::mem::size_of::<RedirectContext>());
        assert_eq!(context.version, 1);
        assert_eq!(context.size as usize, std::mem::size_of::<RedirectContext>());
        assert_eq!(context.session_id, session_id);
        assert_eq!(context.original_destination.ss_family, AF_INET);
        let destination = unsafe {
            std::slice::from_raw_parts(
                (&context.original_destination as *const SOCKADDR_STORAGE).cast::<u8>(),
                std::mem::size_of::<SOCKADDR_STORAGE>(),
            )
        };
        assert_eq!(&destination[2..4], &443u16.to_be_bytes());
        assert_eq!(&destination[4..8], &[198, 51, 100, 10]);

        let mut records = [0u8; 4096];
        let mut record_bytes = 0;
        let result = unsafe {
            WSAIoctl(
                socket,
                SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
                std::ptr::null(),
                0,
                records.as_mut_ptr().cast(),
                records.len() as u32,
                &mut record_bytes,
                std::ptr::null_mut(),
                None,
            )
        };
        assert_eq!(result, 0, "redirect records query failed: {}", unsafe {
            WSAGetLastError()
        });
        assert!(record_bytes > 0);
        let mut payload = [0; 3];
        stream.read_exact(&mut payload).unwrap();
        assert_eq!(&payload, b"C5!");

        wfp::remove().unwrap();
        cleanup.policy = false;
        driver_detach_blocking(session_id).unwrap();
        cleanup.attached = false;
    }

    #[cfg(all(windows, feature = "client", feature = "test"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an elevated Windows host with the clash5 WFP driver loaded"]
    async fn exact_target_tcp_round_trips_through_http_connect_relay() -> anyhow::Result<()> {
        use super::{driver_attach_blocking, driver_detach_blocking, wfp};
        use crate::TcpRedirectRelay;
        use crate::core::manager::CORE_MANAGER;
        use crate::core::paths::{ensure_persistent_state_layout, service_paths};
        use crate::core::process::process_identity;
        use std::net::Ipv4Addr;
        use std::path::PathBuf;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

        struct Cleanup {
            child: Child,
            session_id: u64,
            attached: bool,
            policy: bool,
            record_path: Option<PathBuf>,
        }

        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                if self.policy {
                    let _ = wfp::remove();
                }
                if self.attached {
                    let _ = driver_detach_blocking(self.session_id);
                }
                if let Some(path) = &self.record_path {
                    let _ = std::fs::remove_file(path);
                }
            }
        }

        let session_id = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
        )?;
        let token = "a".repeat(64);
        let proxy = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_port = proxy.local_addr()?.port();
        let relay = TcpRedirectRelay::bind(session_id, proxy_port, &token).await?;
        let relay_port = relay.port()?;
        let (stop_relay, relay_shutdown) = tokio::sync::oneshot::channel();
        let relay_task = tokio::spawn(relay.run(relay_shutdown));
        let proxy_task = tokio::spawn(async move {
            let mut observed = Vec::new();
            for _ in 0..2 {
                let (mut socket, _) = proxy.accept().await?;
                let mut headers = Vec::new();
                loop {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).await?;
                    headers.push(byte[0]);
                    if headers.ends_with(b"\r\n\r\n") {
                        break;
                    }
                    if headers.len() > 4096 {
                        anyhow::bail!("CONNECT request exceeded fixture limit");
                    }
                }
                socket.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
                let mut payload = [0; 3];
                socket.read_exact(&mut payload).await?;
                socket.write_all(b"OK!").await?;
                observed.push((headers, payload));
            }
            Ok::<_, anyhow::Error>(observed)
        });

        let script = r#"Start-Sleep -Seconds 5; foreach ($target in @('198.51.100.10', '2001:db8::10')) { $family = if ($target.Contains(':')) { [System.Net.Sockets.AddressFamily]::InterNetworkV6 } else { [System.Net.Sockets.AddressFamily]::InterNetwork }; $client = [System.Net.Sockets.TcpClient]::new($family); try { $client.Connect($target, 443); $stream = $client.GetStream(); $sent = [Text.Encoding]::ASCII.GetBytes('C5!'); $stream.Write($sent, 0, $sent.Length); $received = New-Object byte[] 3; $count = $stream.Read($received, 0, 3); if ($count -ne 3 -or [Text.Encoding]::ASCII.GetString($received) -ne 'OK!') { exit 9 } } finally { $client.Dispose() } }"#;
        let child = Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        let identity = process_identity(child.id())?.ok_or_else(|| anyhow::anyhow!("target exited before attach"))?;
        let session = ProcessProxySession {
            owner_key: "smoke".to_owned(),
            session_id,
            relay_pid: std::process::id(),
            relay_port,
            targets: vec![ProcessProxyTarget {
                pid: child.id(),
                created_at: identity.started_at,
            }],
        };
        let mut cleanup = Cleanup {
            child,
            session_id,
            attached: false,
            policy: false,
            record_path: None,
        };
        driver_attach_blocking(&session)?;
        cleanup.attached = true;
        wfp::install()?;
        cleanup.policy = true;
        ensure_persistent_state_layout()?;
        cleanup.record_path = Some(service_paths()?.process_proxy_session_path());
        super::persist_record(&RecoveryRecord {
            phase: RecoveryPhase::Active,
            session: session.clone(),
        })
        .await?;

        let observed = tokio::time::timeout(Duration::from_secs(20), proxy_task).await???;
        for ((headers, payload), target) in observed.into_iter().zip(["198.51.100.10:443", "[2001:db8::10]:443"]) {
            let headers = String::from_utf8(headers)?;
            assert!(headers.starts_with(&format!("CONNECT {target} HTTP/1.1\r\n")));
            assert!(headers.contains("Proxy-Authorization: Basic "));
            assert_eq!(&payload, b"C5!");
        }
        let deadline = Instant::now() + Duration::from_secs(10);
        let exit = loop {
            if let Some(exit) = cleanup.child.try_wait()? {
                break exit;
            }
            anyhow::ensure!(Instant::now() < deadline, "target did not receive the relay response");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        anyhow::ensure!(exit.success(), "target did not receive the expected relay response");
        CORE_MANAGER.lock().await.stop_core().await?;
        anyhow::ensure!(!wfp::is_active(), "core stop left WFP filters active");
        anyhow::ensure!(
            super::load_record().await?.is_none(),
            "core stop left the recovery record"
        );
        cleanup.attached = false;
        cleanup.policy = false;
        cleanup.record_path = None;

        cleanup.child = Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 20"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        cleanup.session_id = session_id + 1;
        let recovery_identity = process_identity(cleanup.child.id())?
            .ok_or_else(|| anyhow::anyhow!("recovery target exited before attach"))?;
        let recovery_session = ProcessProxySession {
            session_id: cleanup.session_id,
            targets: vec![ProcessProxyTarget {
                pid: cleanup.child.id(),
                created_at: recovery_identity.started_at,
            }],
            ..session.clone()
        };
        driver_attach_blocking(&recovery_session)?;
        cleanup.attached = true;
        wfp::install()?;
        cleanup.policy = true;
        anyhow::ensure!(wfp::is_active(), "recovery fixture did not install WFP filters");
        cleanup.record_path = Some(service_paths()?.process_proxy_session_path());
        super::persist_record(&RecoveryRecord {
            phase: RecoveryPhase::Active,
            session: recovery_session,
        })
        .await?;
        super::reconcile_process_proxy_session().await?;
        anyhow::ensure!(!wfp::is_active(), "recovery left WFP filters active");
        anyhow::ensure!(
            super::load_record().await?.is_none(),
            "recovery left its session record"
        );
        cleanup.attached = false;
        cleanup.policy = false;
        cleanup.record_path = None;

        let _ = cleanup.child.kill();
        let _ = cleanup.child.wait();
        cleanup.child = Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 20"])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;
        cleanup.session_id = session_id + 2;
        let exit_identity =
            process_identity(cleanup.child.id())?.ok_or_else(|| anyhow::anyhow!("exit target ended before attach"))?;
        let owner = crate::core::auth::AuthenticatedOwner {
            key: "smoke".to_owned(),
            identity: crate::OwnerIdentity::Windows {
                sid: "smoke".to_owned(),
            },
            app_data_root: PathBuf::new(),
        };
        let mut active = crate::core::desired::ActiveOwnerState::from(&owner);
        active.generation = cleanup.session_id;
        let request = ProcessProxyAttachRequest {
            relay_pid: std::process::id(),
            relay_port,
            targets: vec![ProcessProxyTarget {
                pid: cleanup.child.id(),
                created_at: exit_identity.started_at,
            }],
        };
        cleanup.record_path = Some(service_paths()?.process_proxy_session_path());
        cleanup.attached = true;
        cleanup.policy = true;
        anyhow::ensure!(
            matches!(
                super::attach_process_proxy(&owner, &active, &request).await?,
                ProcessProxySessionStatus::Active { .. }
            ),
            "service attach did not activate the exit target"
        );
        let _ = cleanup.child.kill();
        cleanup.child.wait()?;
        let deadline = Instant::now() + Duration::from_secs(10);
        while super::load_record().await?.is_some() {
            anyhow::ensure!(Instant::now() < deadline, "monitor did not detach exited target");
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        anyhow::ensure!(
            matches!(
                super::process_proxy_status(&owner, &active).await,
                ProcessProxySessionStatus::Idle
            ),
            "status did not report an idle session after target exit"
        );
        anyhow::ensure!(!wfp::is_active(), "target exit left WFP filters active");
        anyhow::ensure!(
            super::load_record().await?.is_none(),
            "target exit left its session record"
        );
        cleanup.attached = false;
        cleanup.policy = false;
        cleanup.record_path = None;
        let _ = stop_relay.send(());
        tokio::time::timeout(Duration::from_secs(5), relay_task).await???;
        Ok(())
    }

    #[cfg(all(windows, feature = "client", feature = "test"))]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    #[ignore = "requires an elevated Windows host, the WFP driver, and an external Mihomo Chain fixture"]
    async fn exact_target_tcp_traverses_external_mihomo_chain() -> anyhow::Result<()> {
        use super::{driver_detach_blocking, wfp};
        use crate::TcpRedirectRelay;
        use crate::core::paths::{ensure_persistent_state_layout, service_paths};
        use crate::core::process::process_identity;
        use std::path::PathBuf;
        use std::process::{Child, Command, Stdio};
        use std::time::{Duration, Instant};

        struct Cleanup {
            child: Child,
            session_id: u64,
            record_path: PathBuf,
            attached: bool,
        }

        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = self.child.kill();
                let _ = self.child.wait();
                if self.attached {
                    let _ = wfp::remove();
                    let _ = driver_detach_blocking(self.session_id);
                }
                let _ = std::fs::remove_file(&self.record_path);
            }
        }

        let proxy_port: u16 = std::env::var("CLASH5_M5_MIHOMO_PORT")?.parse()?;
        let target_port: u16 = std::env::var("CLASH5_M5_TARGET_PORT")?.parse()?;
        let token = std::env::var("CLASH5_M5_CHAIN_TOKEN")?;
        let session_id = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
        )?;
        let relay = TcpRedirectRelay::bind(session_id, proxy_port, &token).await?;
        let relay_port = relay.port()?;
        let (stop_relay, relay_shutdown) = tokio::sync::oneshot::channel();
        let relay_task = tokio::spawn(relay.run(relay_shutdown));

        let script = r#"Start-Sleep -Seconds 5; $client = [Net.Sockets.TcpClient]::new([Net.Sockets.AddressFamily]::InterNetwork); $client.ReceiveTimeout = 10000; $client.Connect('127.0.0.1', TARGET_PORT); $stream = $client.GetStream(); $request = [Text.Encoding]::ASCII.GetBytes("GET /ip HTTP/1.1`r`nHost: 127.0.0.1`r`nConnection: close`r`n`r`n"); $stream.Write($request, 0, $request.Length); $reader = [IO.StreamReader]::new($stream); $response = $reader.ReadToEnd(); $client.Dispose(); if ($response -notmatch '203\.0\.113\.27') { exit 9 }"#
            .replace("TARGET_PORT", &target_port.to_string());
        let child = Command::new("powershell.exe")
            .args(["-NoProfile", "-Command", &script])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        let identity = process_identity(child.id())?.ok_or_else(|| anyhow::anyhow!("target exited before attach"))?;
        ensure_persistent_state_layout()?;
        let mut cleanup = Cleanup {
            child,
            session_id,
            record_path: service_paths()?.process_proxy_session_path(),
            attached: true,
        };
        let owner = crate::core::auth::AuthenticatedOwner {
            key: "chain-smoke".to_owned(),
            identity: crate::OwnerIdentity::Windows {
                sid: "chain-smoke".to_owned(),
            },
            app_data_root: PathBuf::new(),
        };
        let mut active = crate::core::desired::ActiveOwnerState::from(&owner);
        active.generation = session_id;
        let request = ProcessProxyAttachRequest {
            relay_pid: std::process::id(),
            relay_port,
            targets: vec![ProcessProxyTarget {
                pid: cleanup.child.id(),
                created_at: identity.started_at,
            }],
        };
        anyhow::ensure!(
            matches!(
                super::attach_process_proxy(&owner, &active, &request).await?,
                ProcessProxySessionStatus::Active { .. }
            ),
            "service did not attach the Chain test target"
        );
        anyhow::ensure!(
            matches!(
                super::process_proxy_status(&owner, &active).await,
                ProcessProxySessionStatus::Active { .. }
            ),
            "service did not verify the driver session before reporting active"
        );
        let deadline = Instant::now() + Duration::from_secs(20);
        let exit = loop {
            if let Some(exit) = cleanup.child.try_wait()? {
                break exit;
            }
            anyhow::ensure!(Instant::now() < deadline, "Chain test target timed out");
            tokio::time::sleep(Duration::from_millis(50)).await;
        };
        anyhow::ensure!(
            exit.success(),
            "Chain test target did not receive the expected response"
        );
        let deadline = Instant::now() + Duration::from_secs(10);
        while super::load_record().await?.is_some() {
            anyhow::ensure!(
                Instant::now() < deadline,
                "service did not detach the Chain test target"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        anyhow::ensure!(!wfp::is_active(), "Chain test left WFP filters active");
        cleanup.attached = false;
        let _ = stop_relay.send(());
        tokio::time::timeout(Duration::from_secs(5), relay_task).await???;
        Ok(())
    }

    #[cfg(windows)]
    #[test]
    fn driver_attach_layout_matches_kernel_protocol() {
        use super::{DriverAttachRequest, DriverQueryResponse, DriverTarget, DriverUpdateRequest};

        assert_eq!(std::mem::size_of::<DriverTarget>(), 16);
        assert_eq!(std::mem::size_of::<DriverAttachRequest>(), 2072);
        assert_eq!(std::mem::size_of::<DriverUpdateRequest>(), 2072);
        assert_eq!(std::mem::size_of::<DriverQueryResponse>(), 2072);
    }

    #[cfg(windows)]
    #[test]
    #[ignore = "requires an elevated Windows host with the clash5 WFP driver loaded"]
    fn driver_target_update_checks_exact_instances_and_session() -> anyhow::Result<()> {
        use super::{driver_attach_blocking, driver_detach_blocking, driver_query_blocking, driver_update_blocking};
        use crate::core::process::process_identity;
        use std::process::{Child, Command, Stdio};

        struct Cleanup {
            children: Vec<Child>,
            session_id: u64,
            attached: bool,
        }

        impl Drop for Cleanup {
            fn drop(&mut self) {
                if self.attached {
                    let _ = driver_detach_blocking(self.session_id);
                }
                for child in &mut self.children {
                    let _ = child.kill();
                    let _ = child.wait();
                }
            }
        }

        let mut cleanup = Cleanup {
            children: Vec::new(),
            session_id: 0,
            attached: false,
        };
        for _ in 0..2 {
            cleanup.children.push(
                Command::new("powershell.exe")
                    .args(["-NoProfile", "-Command", "Start-Sleep -Seconds 30"])
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()?,
            );
        }
        let targets = cleanup
            .children
            .iter()
            .map(|child| {
                let identity = process_identity(child.id())?
                    .ok_or_else(|| anyhow::anyhow!("target exited before the update test"))?;
                Ok(ProcessProxyTarget {
                    pid: child.id(),
                    created_at: identity.started_at,
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        cleanup.session_id = u64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos(),
        )?;
        let mut session = ProcessProxySession {
            owner_key: "smoke".to_owned(),
            session_id: cleanup.session_id,
            relay_pid: std::process::id(),
            relay_port: 1,
            targets: vec![targets[0].clone()],
        };
        driver_attach_blocking(&session)?;
        cleanup.attached = true;
        let attached = driver_query_blocking()?;
        anyhow::ensure!(
            attached.session_id == session.session_id,
            "driver attached the wrong session"
        );
        anyhow::ensure!(
            attached.targets[0].pid == u64::from(targets[0].pid),
            "driver lost the initial target"
        );

        session.targets = vec![targets[1].clone()];
        driver_update_blocking(&session)?;
        let updated = driver_query_blocking()?;
        anyhow::ensure!(
            updated.targets[0].pid == u64::from(targets[1].pid),
            "driver did not publish the new target"
        );
        let mut wrong_session = session.clone();
        wrong_session.session_id += 1;
        anyhow::ensure!(
            driver_update_blocking(&wrong_session).is_err(),
            "foreign session update succeeded"
        );
        let mut stale_target = session.clone();
        stale_target.targets[0].created_at += 1;
        anyhow::ensure!(
            driver_update_blocking(&stale_target).is_err(),
            "stale target update succeeded"
        );
        let unchanged = driver_query_blocking()?;
        anyhow::ensure!(
            unchanged.targets[0].pid == u64::from(targets[1].pid),
            "a rejected update changed the target"
        );
        driver_detach_blocking(session.session_id)?;
        cleanup.attached = false;
        anyhow::ensure!(
            driver_query_blocking().is_err(),
            "detached driver still reported an active session"
        );
        Ok(())
    }

    fn request() -> ProcessProxyAttachRequest {
        ProcessProxyAttachRequest {
            relay_pid: 10,
            relay_port: 17_443,
            targets: vec![ProcessProxyTarget {
                pid: 11,
                created_at: 123,
            }],
        }
    }

    #[test]
    fn recovery_record_reads_legacy_active_session_and_preserves_pending_intent() {
        let session = ProcessProxySession {
            owner_key: "owner".to_owned(),
            session_id: 7,
            relay_pid: 10,
            relay_port: 17_443,
            targets: request().targets,
        };
        let legacy = serde_json::to_value(&session).unwrap();
        let recovered: RecoveryRecord = serde_json::from_value(legacy).unwrap();
        assert_eq!(recovered.phase, RecoveryPhase::Active);
        assert_eq!(recovered.session, session);

        let pending = RecoveryRecord {
            phase: RecoveryPhase::Pending,
            session,
        };
        let recovered: RecoveryRecord = serde_json::from_value(serde_json::to_value(pending).unwrap()).unwrap();
        assert_eq!(recovered.phase, RecoveryPhase::Pending);
    }

    #[test]
    fn relay_never_becomes_a_target() {
        let mut invalid = request();
        invalid.targets[0].pid = invalid.relay_pid;
        assert!(validate_request(&invalid).is_err());
    }

    #[test]
    fn exact_targets_need_creation_time_and_unique_pid() {
        let mut missing_creation_time = request();
        missing_creation_time.targets[0].created_at = 0;
        assert!(validate_request(&missing_creation_time).is_err());

        let mut duplicate = request();
        duplicate.targets.push(duplicate.targets[0].clone());
        assert!(validate_request(&duplicate).is_err());
    }
}
