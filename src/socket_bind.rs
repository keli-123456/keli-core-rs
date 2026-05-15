use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, UdpSocket};

use socket2::{Domain, Protocol, Socket, Type};

pub(crate) fn bind_dual_stack_tcp_listener(listen: SocketAddr) -> io::Result<TcpListener> {
    let listen = dual_stack_wildcard_addr(listen);
    if !is_ipv6_unspecified(listen) {
        return bind_tcp_listener(listen).map_err(|error| bind_addr_error(listen, error));
    }

    match bind_ipv6_tcp_listener(listen) {
        Ok(listener) => Ok(listener),
        Err(error) if should_fallback_to_ipv4(&error) => {
            let fallback = SocketAddr::from((Ipv4Addr::UNSPECIFIED, listen.port()));
            bind_tcp_listener(fallback).map_err(|error| bind_addr_error(fallback, error))
        }
        Err(error) => Err(bind_addr_error(listen, error)),
    }
}

pub(crate) fn bind_dual_stack_udp_socket(listen: SocketAddr) -> io::Result<UdpSocket> {
    let listen = dual_stack_wildcard_addr(listen);
    if !is_ipv6_unspecified(listen) {
        return bind_udp_socket(listen).map_err(|error| bind_addr_error(listen, error));
    }

    match bind_ipv6_udp_socket(listen) {
        Ok(socket) => Ok(socket),
        Err(error) if should_fallback_to_ipv4(&error) => {
            let fallback = SocketAddr::from((Ipv4Addr::UNSPECIFIED, listen.port()));
            bind_udp_socket(fallback).map_err(|error| bind_addr_error(fallback, error))
        }
        Err(error) => Err(bind_addr_error(listen, error)),
    }
}

fn dual_stack_wildcard_addr(listen: SocketAddr) -> SocketAddr {
    if matches!(listen, SocketAddr::V4(addr) if addr.ip().is_unspecified()) {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, listen.port()))
    } else {
        listen
    }
}

fn bind_ipv6_tcp_listener(listen: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_reuse_address(true)?;
    socket.set_only_v6(false)?;
    socket.bind(&listen.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

fn bind_ipv6_udp_socket(listen: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_only_v6(false)?;
    socket.bind(&listen.into())?;
    Ok(socket.into())
}

fn bind_tcp_listener(listen: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(
        Domain::for_address(listen),
        Type::STREAM,
        Some(Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    socket.bind(&listen.into())?;
    socket.listen(1024)?;
    Ok(socket.into())
}

fn bind_udp_socket(listen: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(listen),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    socket.bind(&listen.into())?;
    Ok(socket.into())
}

fn is_ipv6_unspecified(listen: SocketAddr) -> bool {
    matches!(listen, SocketAddr::V6(addr) if addr.ip().is_unspecified())
}

fn should_fallback_to_ipv4(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::AddrNotAvailable | io::ErrorKind::Unsupported
    ) || matches!(error.raw_os_error(), Some(47 | 49 | 97 | 10047 | 10049))
}

fn bind_addr_error(listen: SocketAddr, error: io::Error) -> io::Error {
    io::Error::new(error.kind(), format!("at {listen}: {error}"))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{Ipv6Addr, SocketAddr, TcpStream, UdpSocket};
    use std::thread;
    use std::time::Duration;

    use super::{bind_dual_stack_tcp_listener, bind_dual_stack_udp_socket};

    #[test]
    fn wildcard_tcp_listener_accepts_ipv4_clients() {
        let _guard = crate::test_support::network_test_lock();
        let listener = bind_dual_stack_tcp_listener(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
            .expect("bind tcp listener");
        let port = listener.local_addr().expect("listener addr").port();

        let accept = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept ipv4 client");
            let mut byte = [0_u8; 1];
            stream.read_exact(&mut byte).expect("read byte");
            byte[0]
        });

        let mut client =
            TcpStream::connect(SocketAddr::from(([127, 0, 0, 1], port))).expect("connect ipv4");
        client.write_all(&[7]).expect("write byte");

        assert_eq!(accept.join().expect("join accept"), 7);
    }

    #[test]
    fn wildcard_udp_socket_receives_ipv4_datagrams() {
        let _guard = crate::test_support::network_test_lock();
        let socket = bind_dual_stack_udp_socket(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
            .expect("bind udp socket");
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let port = socket.local_addr().expect("socket addr").port();
        let client = UdpSocket::bind("127.0.0.1:0").expect("client bind");
        client
            .send_to(&[9], SocketAddr::from(([127, 0, 0, 1], port)))
            .expect("send ipv4 datagram");

        let mut buf = [0_u8; 1];
        let (read, _) = socket.recv_from(&mut buf).expect("recv datagram");
        assert_eq!(read, 1);
        assert_eq!(buf[0], 9);
    }

    #[test]
    fn tcp_listener_rebinds_same_port_after_close() {
        let _guard = crate::test_support::network_test_lock();
        let listener = bind_dual_stack_tcp_listener(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)))
            .expect("bind first listener");
        let port = listener.local_addr().expect("listener addr").port();
        drop(listener);

        let listener =
            bind_dual_stack_tcp_listener(SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)))
                .expect("rebind listener");
        assert_eq!(listener.local_addr().expect("listener addr").port(), port);
    }
}
