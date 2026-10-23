use crate::core::auth::ServiceError;
use std::sync::{Mutex, OnceLock};
use windows_sys::{
    Win32::{
        Foundation::HANDLE,
        NetworkManagement::WindowsFilteringPlatform::{
            FWP_ACTION_CALLOUT_TERMINATING, FWP_MATCH_EQUAL, FWP_UINT8, FWPM_CALLOUT0, FWPM_CONDITION_IP_PROTOCOL,
            FWPM_FILTER_CONDITION0, FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED, FWPM_FILTER0,
            FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, FWPM_PROVIDER0,
            FWPM_SESSION_FLAG_DYNAMIC, FWPM_SESSION0, FWPM_SUBLAYER0, FwpmCalloutAdd0, FwpmEngineClose0,
            FwpmEngineOpen0, FwpmFilterAdd0, FwpmFilterGetById0, FwpmFreeMemory0, FwpmProviderAdd0, FwpmSubLayerAdd0,
            FwpmTransactionAbort0, FwpmTransactionBegin0, FwpmTransactionCommit0,
        },
        System::Rpc::RPC_C_AUTHN_WINNT,
    },
    core::GUID,
};

const PROVIDER: GUID = GUID::from_u128(0x39d1d3b9_609c_4e90_8b89_0a14014394e3);
const SUBLAYER: GUID = GUID::from_u128(0x4a34a91a_0b4c_4534_9714_29b6aab18e60);
const CALLOUT_V4: GUID = GUID::from_u128(0x29c874bb_6e17_4d6a_9e51_49210c3b4ed4);
const CALLOUT_V6: GUID = GUID::from_u128(0xf5227b0e_0ad0_4b46_ae64_2a992002e490);

#[derive(Clone, Copy)]
struct ActivePolicy {
    engine: usize,
    filters: Option<[u64; 2]>,
}

fn active_engine() -> &'static Mutex<Option<ActivePolicy>> {
    static ENGINE: OnceLock<Mutex<Option<ActivePolicy>>> = OnceLock::new();
    ENGINE.get_or_init(|| Mutex::new(None))
}

pub(super) fn install() -> Result<(), ServiceError> {
    let mut active = active_engine()
        .lock()
        .map_err(|_| unavailable("WFP session lock is poisoned"))?;
    if active.is_some() {
        return Err(unavailable("a WFP session is already active"));
    }

    let session = FWPM_SESSION0 {
        flags: FWPM_SESSION_FLAG_DYNAMIC,
        ..Default::default()
    };
    let mut engine: HANDLE = std::ptr::null_mut();
    check(
        unsafe {
            FwpmEngineOpen0(
                std::ptr::null(),
                RPC_C_AUTHN_WINNT,
                std::ptr::null(),
                &session,
                &mut engine,
            )
        },
        "open WFP engine",
    )?;

    let result = (|| {
        check(unsafe { FwpmTransactionBegin0(engine, 0) }, "begin WFP transaction")?;
        let filters = match add_policy(engine) {
            Ok(filters) => filters,
            Err(error) => {
                unsafe { FwpmTransactionAbort0(engine) };
                return Err(error);
            }
        };
        if let Err(error) = check(unsafe { FwpmTransactionCommit0(engine) }, "commit WFP transaction") {
            unsafe { FwpmTransactionAbort0(engine) };
            return Err(error);
        }
        Ok(filters)
    })();
    let filters = match result {
        Ok(filters) => filters,
        Err(error) => {
            if let Err(close_error) = check(unsafe { FwpmEngineClose0(engine) }, "close failed WFP session") {
                *active = Some(ActivePolicy {
                    engine: engine as usize,
                    filters: None,
                });
                return Err(ServiceError::process_proxy_recovery_required(format!(
                    "{error}; {close_error}"
                )));
            }
            return Err(error);
        }
    };
    *active = Some(ActivePolicy {
        engine: engine as usize,
        filters: Some(filters),
    });
    Ok(())
}

pub(super) fn remove() -> Result<(), ServiceError> {
    let mut active = active_engine()
        .lock()
        .map_err(|_| unavailable("WFP session lock is poisoned"))?;
    let Some(policy) = *active else {
        return Ok(());
    };
    check(unsafe { FwpmEngineClose0(policy.engine as HANDLE) }, "close WFP engine")?;
    *active = None;
    Ok(())
}

pub(super) fn is_active() -> bool {
    active_engine().lock().is_ok_and(|active| {
        let Some(ActivePolicy {
            engine,
            filters: Some(filters),
        }) = *active
        else {
            return false;
        };
        filters
            .into_iter()
            .zip([
                (FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, CALLOUT_V4),
                (FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, CALLOUT_V6),
            ])
            .all(|(id, (layer, callout))| filter_is_active(engine as HANDLE, id, layer, callout))
    })
}

fn filter_is_active(engine: HANDLE, id: u64, layer: GUID, callout: GUID) -> bool {
    let mut filter = std::ptr::null_mut();
    if unsafe { FwpmFilterGetById0(engine, id, &mut filter) } != 0 || filter.is_null() {
        return false;
    }
    let found = unsafe {
        guid_eq((*filter).layerKey, layer)
            && (*filter).action.r#type == FWP_ACTION_CALLOUT_TERMINATING
            && guid_eq((*filter).action.Anonymous.calloutKey, callout)
    };
    unsafe { FwpmFreeMemory0((&mut filter as *mut *mut FWPM_FILTER0).cast()) };
    found
}

fn add_policy(engine: HANDLE) -> Result<[u64; 2], ServiceError> {
    let provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER,
        ..Default::default()
    };
    check(
        unsafe { FwpmProviderAdd0(engine, &provider, std::ptr::null_mut()) },
        "add WFP provider",
    )?;
    let mut provider_key = PROVIDER;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER,
        providerKey: &mut provider_key,
        weight: 0x100,
        ..Default::default()
    };
    check(
        unsafe { FwpmSubLayerAdd0(engine, &sublayer, std::ptr::null_mut()) },
        "add WFP sublayer",
    )?;

    let mut filters = [0; 2];
    for (index, (layer, callout_key)) in [
        (FWPM_LAYER_ALE_CONNECT_REDIRECT_V4, CALLOUT_V4),
        (FWPM_LAYER_ALE_CONNECT_REDIRECT_V6, CALLOUT_V6),
    ]
    .into_iter()
    .enumerate()
    {
        let callout = FWPM_CALLOUT0 {
            calloutKey: callout_key,
            providerKey: &mut provider_key,
            applicableLayer: layer,
            ..Default::default()
        };
        check(
            unsafe { FwpmCalloutAdd0(engine, &callout, std::ptr::null_mut(), std::ptr::null_mut()) },
            "add WFP callout",
        )?;

        let mut tcp = FWPM_FILTER_CONDITION0 {
            fieldKey: FWPM_CONDITION_IP_PROTOCOL,
            matchType: FWP_MATCH_EQUAL,
            ..Default::default()
        };
        tcp.conditionValue.r#type = FWP_UINT8;
        tcp.conditionValue.Anonymous.uint8 = 6;
        let mut filter = FWPM_FILTER0 {
            providerKey: &mut provider_key,
            layerKey: layer,
            subLayerKey: SUBLAYER,
            flags: FWPM_FILTER_FLAG_PERMIT_IF_CALLOUT_UNREGISTERED,
            numFilterConditions: 1,
            filterCondition: &mut tcp,
            ..Default::default()
        };
        filter.action.r#type = FWP_ACTION_CALLOUT_TERMINATING;
        filter.action.Anonymous.calloutKey = callout_key;
        check(
            unsafe { FwpmFilterAdd0(engine, &filter, std::ptr::null_mut(), &mut filters[index]) },
            "add WFP redirect filter",
        )?;
    }
    Ok(filters)
}

fn check(code: u32, action: &str) -> Result<(), ServiceError> {
    if code == 0 {
        Ok(())
    } else {
        Err(unavailable(format!("{action} failed with Windows error {code}")))
    }
}

fn guid_eq(left: GUID, right: GUID) -> bool {
    left.data1 == right.data1 && left.data2 == right.data2 && left.data3 == right.data3 && left.data4 == right.data4
}

fn unavailable(message: impl Into<String>) -> ServiceError {
    ServiceError::process_proxy_unavailable(message)
}
