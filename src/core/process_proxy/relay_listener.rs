use crate::core::auth::ServiceError;
use std::mem::size_of;
use windows_sys::Win32::{
    Foundation::ERROR_INSUFFICIENT_BUFFER,
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP_STATE_LISTEN, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};

const MAX_TABLE_BYTES: usize = 16 * 1024 * 1024;

pub(super) fn verify(pid: u32, port: u16) -> Result<(), ServiceError> {
    if !owned_loopback_listener(AF_INET.into(), pid, port)? || !owned_loopback_listener(AF_INET6.into(), pid, port)? {
        return Err(ServiceError::invalid_process_proxy_session(
            "the claimed relay must own IPv4 and IPv6 loopback listeners on its port",
        ));
    }
    Ok(())
}

fn owned_loopback_listener(family: u32, pid: u32, port: u16) -> Result<bool, ServiceError> {
    let (table, used) = tcp_listener_table(family)?;
    let row_size = if family == u32::from(AF_INET) {
        size_of::<MIB_TCPROW_OWNER_PID>()
    } else {
        size_of::<MIB_TCP6ROW_OWNER_PID>()
    };
    if used < size_of::<u32>() || (table[0] as usize) > (used - size_of::<u32>()) / row_size {
        return Err(ServiceError::process_proxy_unavailable(
            "the Windows TCP listener table is incomplete",
        ));
    }
    for index in 0..table[0] as usize {
        let row = unsafe { table.as_ptr().cast::<u8>().add(size_of::<u32>() + index * row_size) };
        if family == u32::from(AF_INET) {
            let row = unsafe { row.cast::<MIB_TCPROW_OWNER_PID>().read_unaligned() };
            if row.dwState == MIB_TCP_STATE_LISTEN as u32
                && row.dwOwningPid == pid
                && u16::from_be(row.dwLocalPort as u16) == port
                && row.dwLocalAddr.to_ne_bytes() == [127, 0, 0, 1]
            {
                return Ok(true);
            }
        } else {
            let row = unsafe { row.cast::<MIB_TCP6ROW_OWNER_PID>().read_unaligned() };
            if row.dwState == MIB_TCP_STATE_LISTEN as u32
                && row.dwOwningPid == pid
                && u16::from_be(row.dwLocalPort as u16) == port
                && row.ucLocalAddr == std::net::Ipv6Addr::LOCALHOST.octets()
            {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

fn tcp_listener_table(family: u32) -> Result<(Vec<u32>, usize), ServiceError> {
    let mut table = vec![0_u32; 1024];
    for _ in 0..5 {
        let mut size = u32::try_from(table.len() * size_of::<u32>())
            .map_err(|_| ServiceError::process_proxy_unavailable("the Windows TCP listener table is too large"))?;
        let status = unsafe {
            GetExtendedTcpTable(
                table.as_mut_ptr().cast(),
                &mut size,
                0,
                family,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status == 0 {
            return Ok((table, size as usize));
        }
        if status != ERROR_INSUFFICIENT_BUFFER || size as usize > MAX_TABLE_BYTES {
            return Err(ServiceError::process_proxy_unavailable(format!(
                "Windows could not enumerate TCP listeners: {}",
                std::io::Error::from_raw_os_error(status as i32)
            )));
        }
        table.resize((size as usize).div_ceil(size_of::<u32>()) + 64, 0);
    }
    Err(ServiceError::process_proxy_unavailable(
        "the Windows TCP listener table changed during enumeration",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr, TcpListener};

    #[test]
    fn relay_requires_both_loopback_listeners_owned_by_the_claimed_process() {
        let ipv4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
        let port = ipv4.local_addr().unwrap().port();
        let pid = std::process::id();
        assert!(owned_loopback_listener(AF_INET.into(), pid, port).unwrap());
        assert!(!owned_loopback_listener(AF_INET6.into(), pid, port).unwrap());
        assert!(verify(pid, port).is_err());

        let _ipv6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).unwrap();
        assert!(verify(pid, port).is_ok());
        assert!(verify(pid.wrapping_add(1), port).is_err());
    }

    #[test]
    fn wildcard_listener_is_not_accepted_as_a_loopback_relay() {
        let wildcard = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        let port = wildcard.local_addr().unwrap().port();
        assert!(!owned_loopback_listener(AF_INET.into(), std::process::id(), port).unwrap());
    }
}
