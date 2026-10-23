use base64::{Engine as _, engine::general_purpose::STANDARD};
use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    os::windows::io::AsRawSocket,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpSocket, TcpStream},
    sync::{Semaphore, oneshot},
    task::JoinSet,
};
use windows_sys::Win32::Networking::WinSock::{
    AF_INET, AF_INET6, SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT, SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
    SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS, SOCKADDR_STORAGE, WSAGetLastError, WSAIoctl,
};

const MAX_ACTIVE_FLOWS: usize = 512;
const MAX_REDIRECT_RECORD: usize = 65_536;
const MAX_PROXY_RESPONSE: usize = 8_192;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

#[repr(C)]
struct RedirectContext {
    version: u32,
    size: u32,
    session_id: u64,
    original_destination: SOCKADDR_STORAGE,
}

struct RedirectedFlow {
    destination: SocketAddr,
    records: Vec<u8>,
}

struct RelayConfig {
    session_id: u64,
    proxy_port: u16,
    authorization: String,
}

/// A session-bound relay for TCP sockets redirected by the clash5 WFP driver.
/// Bind before asking the privileged service to attach, then run until detach.
pub struct TcpRedirectRelay {
    ipv4: TcpListener,
    ipv6: TcpListener,
    config: Arc<RelayConfig>,
}

impl TcpRedirectRelay {
    pub async fn bind(session_id: u64, proxy_port: u16, token: &str) -> io::Result<Self> {
        if session_id == 0
            || proxy_port == 0
            || token.len() != 64
            || !token.bytes().all(|byte| byte.is_ascii_hexdigit())
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "invalid process-proxy session configuration",
            ));
        }
        let ipv4 = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let port = ipv4.local_addr()?.port();
        let ipv6 = TcpListener::bind((Ipv6Addr::LOCALHOST, port)).await?;
        Ok(Self {
            ipv4,
            ipv6,
            config: Arc::new(RelayConfig {
                session_id,
                proxy_port,
                authorization: STANDARD.encode(format!("clash5:{token}")),
            }),
        })
    }

    pub fn port(&self) -> io::Result<u16> {
        Ok(self.ipv4.local_addr()?.port())
    }

    pub async fn run(self, mut shutdown: oneshot::Receiver<()>) -> io::Result<()> {
        let mut tasks = JoinSet::new();
        let slots = Arc::new(Semaphore::new(MAX_ACTIVE_FLOWS));
        let result = loop {
            tokio::select! {
                biased;
                _ = &mut shutdown => break Ok(()),
                Some(_) = tasks.join_next(), if !tasks.is_empty() => {},
                accepted = self.ipv4.accept() => match accepted {
                    Ok((stream, _)) => spawn_flow(stream, &self.config, &slots, &mut tasks),
                    Err(error) => break Err(error),
                },
                accepted = self.ipv6.accept() => match accepted {
                    Ok((stream, _)) => spawn_flow(stream, &self.config, &slots, &mut tasks),
                    Err(error) => break Err(error),
                },
            }
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
}

fn spawn_flow(stream: TcpStream, config: &Arc<RelayConfig>, slots: &Arc<Semaphore>, tasks: &mut JoinSet<()>) {
    let Ok(permit) = Arc::clone(slots).try_acquire_owned() else {
        return;
    };
    let config = Arc::clone(config);
    tasks.spawn(async move {
        let _permit = permit;
        let Ok(flow) = query_redirected_flow(&stream, config.session_id) else {
            return;
        };
        let _ = forward_connect(stream, &config, flow.destination, Some(&flow.records)).await;
    });
}

fn query_redirected_flow(stream: &TcpStream, session_id: u64) -> io::Result<RedirectedFlow> {
    let socket = stream.as_raw_socket() as usize;
    let mut context = RedirectContext {
        version: 0,
        size: 0,
        session_id: 0,
        original_destination: SOCKADDR_STORAGE::default(),
    };
    let mut bytes = 0;
    let result = unsafe {
        WSAIoctl(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_CONTEXT,
            std::ptr::null(),
            0,
            (&mut context as *mut RedirectContext).cast(),
            size_of_u32::<RedirectContext>(),
            &mut bytes,
            std::ptr::null_mut(),
            None,
        )
    };
    if result != 0 {
        return Err(last_wsa_error());
    }
    if bytes != size_of_u32::<RedirectContext>()
        || context.version != 1
        || context.size != size_of_u32::<RedirectContext>()
        || context.session_id != session_id
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid WFP redirect context",
        ));
    }
    let destination = original_destination(&context.original_destination)?;

    let mut records = vec![0_u8; MAX_REDIRECT_RECORD];
    bytes = 0;
    let result = unsafe {
        WSAIoctl(
            socket,
            SIO_QUERY_WFP_CONNECTION_REDIRECT_RECORDS,
            std::ptr::null(),
            0,
            records.as_mut_ptr().cast(),
            size_of_u32::<[u8; MAX_REDIRECT_RECORD]>(),
            &mut bytes,
            std::ptr::null_mut(),
            None,
        )
    };
    if result != 0 {
        return Err(last_wsa_error());
    }
    if bytes == 0 || bytes as usize > records.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid WFP redirect record",
        ));
    }
    records.truncate(bytes as usize);
    Ok(RedirectedFlow { destination, records })
}

fn original_destination(storage: &SOCKADDR_STORAGE) -> io::Result<SocketAddr> {
    let bytes = unsafe {
        std::slice::from_raw_parts(
            (storage as *const SOCKADDR_STORAGE).cast::<u8>(),
            std::mem::size_of::<SOCKADDR_STORAGE>(),
        )
    };
    let port = u16::from_be_bytes([bytes[2], bytes[3]]);
    if port == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "redirected destination has no port",
        ));
    }
    match storage.ss_family {
        AF_INET => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7])),
            port,
        )),
        AF_INET6 => {
            if bytes[24..28] != [0; 4] {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "scoped IPv6 redirect is unsupported",
                ));
            }
            let mut address = [0_u8; 16];
            address.copy_from_slice(&bytes[8..24]);
            Ok(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(address)), port))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported redirected address family",
        )),
    }
}

async fn forward_connect(
    mut redirected: TcpStream,
    config: &RelayConfig,
    destination: SocketAddr,
    records: Option<&[u8]>,
) -> io::Result<()> {
    let socket = TcpSocket::new_v4()?;
    if let Some(records) = records {
        set_redirect_records(socket.as_raw_socket() as usize, records)?;
    }
    let proxy_address = SocketAddr::from((Ipv4Addr::LOCALHOST, config.proxy_port));
    let mut proxy = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(proxy_address)).await??;
    let authority = destination.to_string();
    let request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Authorization: Basic {}\r\n\r\n",
        config.authorization
    );
    proxy.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    let header_end = tokio::time::timeout(CONNECT_TIMEOUT, async {
        loop {
            let mut buffer = [0_u8; 1024];
            let count = proxy.read(&mut buffer).await?;
            if count == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "proxy closed before CONNECT",
                ));
            }
            response.extend_from_slice(&buffer[..count]);
            if let Some(end) = response.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                let header_end = end + 4;
                if header_end <= MAX_PROXY_RESPONSE {
                    return Ok(header_end);
                }
            }
            if response.len() >= MAX_PROXY_RESPONSE {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "proxy response header is too large",
                ));
            }
        }
    })
    .await??;
    let status = response.split(|byte| *byte == b'\r').next().unwrap_or_default();
    if !status.starts_with(b"HTTP/1.1 200 ") && !status.starts_with(b"HTTP/1.0 200 ") {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "chain listener rejected CONNECT",
        ));
    }
    redirected.write_all(&response[header_end..]).await?;
    tokio::io::copy_bidirectional(&mut redirected, &mut proxy).await?;
    Ok(())
}

fn set_redirect_records(socket: usize, records: &[u8]) -> io::Result<()> {
    let mut bytes = 0;
    let result = unsafe {
        WSAIoctl(
            socket,
            SIO_SET_WFP_CONNECTION_REDIRECT_RECORDS,
            records.as_ptr().cast(),
            u32::try_from(records.len())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "record too large"))?,
            std::ptr::null_mut(),
            0,
            &mut bytes,
            std::ptr::null_mut(),
            None,
        )
    };
    if result != 0 {
        return Err(last_wsa_error());
    }
    Ok(())
}

fn last_wsa_error() -> io::Error {
    io::Error::from_raw_os_error(unsafe { WSAGetLastError() })
}

const fn size_of_u32<T>() -> u32 {
    std::mem::size_of::<T>() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn authenticated_connect_forwards_payload_to_the_selected_proxy() -> io::Result<()> {
        let proxy = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let proxy_port = proxy.local_addr()?.port();
        let incoming = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await?;
        let incoming_port = incoming.local_addr()?.port();
        let token = "a".repeat(64);
        let config = RelayConfig {
            session_id: 7,
            proxy_port,
            authorization: STANDARD.encode(format!("clash5:{token}")),
        };
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy.accept().await?;
            let mut request = Vec::new();
            loop {
                let mut byte = [0];
                stream.read_exact(&mut byte).await?;
                request.push(byte[0]);
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            stream.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n").await?;
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await?;
            stream.write_all(b"pong").await?;
            Ok::<_, io::Error>((request, payload))
        });
        let client_task = tokio::spawn(async move {
            let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, incoming_port)).await?;
            client.write_all(b"ping").await?;
            let mut payload = [0; 4];
            client.read_exact(&mut payload).await?;
            client.shutdown().await?;
            Ok::<_, io::Error>(payload)
        });
        let (accepted, _) = incoming.accept().await?;
        let destination = SocketAddr::from(([198, 51, 100, 10], 443));
        tokio::time::timeout(
            Duration::from_secs(5),
            forward_connect(accepted, &config, destination, None),
        )
        .await??;
        let (request, payload) = proxy_task.await??;
        assert!(request.starts_with(b"CONNECT 198.51.100.10:443 HTTP/1.1\r\n"));
        assert!(
            String::from_utf8_lossy(&request).contains(&format!("Proxy-Authorization: Basic {}", config.authorization))
        );
        assert_eq!(&payload, b"ping");
        assert_eq!(&client_task.await??, b"pong");
        Ok(())
    }

    #[tokio::test]
    async fn binds_both_loopback_families_on_one_session_port() -> io::Result<()> {
        let relay = TcpRedirectRelay::bind(7, 8080, &"a".repeat(64)).await?;
        assert_eq!(relay.port()?, relay.ipv6.local_addr()?.port());
        assert_eq!(relay.ipv4.local_addr()?.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
        assert_eq!(relay.ipv6.local_addr()?.ip(), IpAddr::V6(Ipv6Addr::LOCALHOST));
        Ok(())
    }
}
