use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use quinn::{AckFrequencyConfig, VarInt};
use socket2::SockRef;

use crate::socket_bind::bind_dual_stack_udp_socket;

const PROXY_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const PROXY_RECEIVE_WINDOW: u32 = 32 * 1024 * 1024;
const PROXY_SEND_WINDOW: u64 = 32 * 1024 * 1024;
const PROXY_MAX_CONCURRENT_STREAMS: u32 = 1024;
const PROXY_UDP_SOCKET_BUFFER_SIZE: usize = 4 * 1024 * 1024;
const PROXY_ACK_ELICITING_THRESHOLD: u32 = 8;
const PROXY_ACK_MAX_DELAY_MS: u64 = 5;
const PROXY_INITIAL_RTT_MS: u64 = 50;

pub(crate) fn server_endpoint_with_tuned_udp_socket(
    server_config: quinn::ServerConfig,
    listen: SocketAddr,
) -> io::Result<quinn::Endpoint> {
    let socket = bind_quic_udp_socket(listen)?;
    tune_quic_udp_socket(&socket);
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(server_config),
        socket,
        Arc::new(quinn::TokioRuntime),
    )
}

pub(crate) fn bind_quic_udp_socket(listen: SocketAddr) -> io::Result<UdpSocket> {
    bind_dual_stack_udp_socket(listen)
}

pub(crate) fn tune_quic_udp_socket(socket: &UdpSocket) {
    let socket = SockRef::from(socket);
    let _ = socket.set_recv_buffer_size(PROXY_UDP_SOCKET_BUFFER_SIZE);
    let _ = socket.set_send_buffer_size(PROXY_UDP_SOCKET_BUFFER_SIZE);
}

pub(crate) fn apply_proxy_quic_transport_defaults(transport: &mut quinn::TransportConfig) {
    let mut ack_frequency = AckFrequencyConfig::default();
    ack_frequency
        .ack_eliciting_threshold(VarInt::from_u32(PROXY_ACK_ELICITING_THRESHOLD))
        .max_ack_delay(Some(std::time::Duration::from_millis(
            PROXY_ACK_MAX_DELAY_MS,
        )));

    transport
        .stream_receive_window(VarInt::from_u32(PROXY_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(PROXY_RECEIVE_WINDOW))
        .send_window(PROXY_SEND_WINDOW)
        .send_fairness(false)
        .initial_rtt(Duration::from_millis(PROXY_INITIAL_RTT_MS))
        .ack_frequency_config(Some(ack_frequency))
        .max_concurrent_bidi_streams(VarInt::from_u32(PROXY_MAX_CONCURRENT_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(PROXY_MAX_CONCURRENT_STREAMS));
}

pub(crate) fn apply_quic_congestion_control(
    transport: &mut quinn::TransportConfig,
    value: &str,
    default_value: &str,
    context: &str,
) -> io::Result<()> {
    let normalized = normalize_quic_congestion_control(value);
    let selected = if normalized.is_empty() {
        normalize_quic_congestion_control(default_value)
    } else {
        normalized
    };
    match selected.as_str() {
        "cubic" => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
            Ok(())
        }
        "bbr" => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
            Ok(())
        }
        "new_reno" | "newreno" | "reno" => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
            Ok(())
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported {context} congestion_control {other}"),
        )),
    }
}

pub(crate) fn is_supported_quic_congestion_control(value: &str) -> bool {
    matches!(
        normalize_quic_congestion_control(value).as_str(),
        "" | "cubic" | "bbr" | "new_reno" | "newreno" | "reno"
    )
}

pub(crate) fn normalize_quic_congestion_control(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_quic_defaults_use_low_initial_rtt_for_proxy_streams() {
        let mut transport = quinn::TransportConfig::default();

        apply_proxy_quic_transport_defaults(&mut transport);

        let debug = format!("{transport:?}");
        assert!(debug.contains("initial_rtt: 50ms"));
        assert!(debug.contains("send_fairness: false"));
        assert!(debug.contains("ack_frequency_config: Some"));
    }
}
