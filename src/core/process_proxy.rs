use crate::core::auth::{AuthenticatedOwner, ServiceError};
use crate::core::desired::ActiveOwnerState;
use crate::core::paths::service_paths;
use crate::{PROCESS_PROXY_MAX_TARGETS, ProcessProxyAttachRequest, ProcessProxySession, ProcessProxySessionStatus};
use anyhow::{Context as _, Result};
use serde::{Deserialize, Serialize};
use std::sync::{
    OnceLock,
    atomic::{AtomicBool, Ordering},
};

#[cfg(windows)]
mod wfp;

const DRIVER_PROTOCOL_VERSION: u32 = 2;
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
    Ok(ProcessProxySessionStatus::Active { session })
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
                RecoveryPhase::Active if policy_is_active().await => ProcessProxySessionStatus::Active {
                    session: record.session,
                },
                RecoveryPhase::Active => ProcessProxySessionStatus::RecoveryRequired {
                    detail: "the WFP redirect filters are unavailable".to_owned(),
                },
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

/// Runs before restoring normal service work. A surviving record is never assumed idle:
/// the service first asks the driver to detach it, then removes the record.
pub async fn reconcile_process_proxy_session() -> Result<()> {
    let _operation = operation_lock().lock().await;
    let Some(record) = load_record().await? else {
        return Ok(());
    };
    policy_remove().await.map_err(|error| anyhow::anyhow!(error.message))?;
    driver_detach(record.session.session_id)
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
    if request.targets.is_empty() || request.targets.len() > PROCESS_PROXY_MAX_TARGETS {
        return Err(ServiceError::invalid_process_proxy_session(format!(
            "target count must be between 1 and {PROCESS_PROXY_MAX_TARGETS}"
        )));
    }
    let mut seen = std::collections::BTreeSet::new();
    for target in &request.targets {
        if target.pid == 0 || target.created_at == 0 {
            return Err(ServiceError::invalid_process_proxy_session(
                "each target requires a PID and creation timestamp",
            ));
        }
        if target.pid == request.relay_pid {
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
const IOCTL_ATTACH_SESSION: u32 = 0x0012_a004;
#[cfg(windows)]
const IOCTL_DETACH_SESSION: u32 = 0x0012_a008;

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
fn driver_detach_blocking(session_id: u64) -> std::result::Result<(), ServiceError> {
    let request = DriverDetachRequest {
        version: DRIVER_PROTOCOL_VERSION,
        size: std::mem::size_of::<DriverDetachRequest>() as u32,
        session_id,
    };
    send_driver_ioctl(IOCTL_DETACH_SESSION, &request)
}

#[cfg(windows)]
fn send_driver_ioctl<T>(code: u32, request: &T) -> std::result::Result<(), ServiceError> {
    use std::ffi::c_void;
    use windows_sys::Win32::{
        Foundation::{CloseHandle, GENERIC_WRITE, INVALID_HANDLE_VALUE},
        Storage::FileSystem::{CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING},
        System::IO::DeviceIoControl,
    };

    let path = r"\\.\Clash5ProcessProxy\0".encode_utf16().collect::<Vec<_>>();
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
    use crate::{ProcessProxyAttachRequest, ProcessProxySession, ProcessProxyTarget};

    #[cfg(windows)]
    #[test]
    fn driver_attach_layout_matches_kernel_protocol() {
        use super::{DriverAttachRequest, DriverTarget};

        assert_eq!(std::mem::size_of::<DriverTarget>(), 16);
        assert_eq!(std::mem::size_of::<DriverAttachRequest>(), 2072);
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
