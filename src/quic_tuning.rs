use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use quinn::{AckFrequencyConfig, IdleTimeout, VarInt};
use socket2::SockRef;

use crate::quic_resources::{available_parallelism_count, memory_limit_mib, open_file_soft_limit};
use crate::socket_bind::bind_dual_stack_udp_socket;

const MIB_U32: u32 = 1024 * 1024;
const MIB_U64: u64 = 1024 * 1024;
const MIB_USIZE: usize = 1024 * 1024;
const DEFAULT_PROXY_STREAM_RECEIVE_WINDOW_MIB: u32 = 8;
const DEFAULT_PROXY_RECEIVE_WINDOW_MIB: u32 = 20;
const DEFAULT_PROXY_MAX_CONCURRENT_STREAMS: u32 = 1024;
const DEFAULT_PROXY_UDP_SOCKET_BUFFER_MIB: usize = 4;
const DEFAULT_PROXY_ACK_ELICITING_THRESHOLD: u32 = 8;
const DEFAULT_PROXY_ACK_MAX_DELAY_MS: u64 = 5;
const DEFAULT_PROXY_INITIAL_RTT_MS: u64 = 50;
const DEFAULT_PROXY_MAX_IDLE_TIMEOUT_SECS: u64 = 30;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProxyQuicTuning {
    pub stream_receive_window_mib: u32,
    pub receive_window_mib: u32,
    pub send_window_mib: u32,
    pub max_concurrent_streams: u32,
    pub udp_socket_buffer_mib: usize,
    pub ack_eliciting_threshold: u32,
    pub ack_max_delay_ms: u64,
    pub initial_rtt_ms: u64,
    pub max_idle_timeout_secs: u64,
}

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
    let tuning = proxy_quic_tuning();
    let buffer_size = tuning.udp_socket_buffer_mib.saturating_mul(MIB_USIZE);
    let _ = socket.set_recv_buffer_size(buffer_size);
    let _ = socket.set_send_buffer_size(buffer_size);
}

pub(crate) fn apply_proxy_quic_transport_defaults(transport: &mut quinn::TransportConfig) {
    let tuning = proxy_quic_tuning();
    let mut ack_frequency = AckFrequencyConfig::default();
    ack_frequency
        .ack_eliciting_threshold(VarInt::from_u32(tuning.ack_eliciting_threshold))
        .max_ack_delay(Some(std::time::Duration::from_millis(
            tuning.ack_max_delay_ms,
        )));

    transport
        .stream_receive_window(VarInt::from_u32(
            tuning.stream_receive_window_mib.saturating_mul(MIB_U32),
        ))
        .receive_window(VarInt::from_u32(
            tuning.receive_window_mib.saturating_mul(MIB_U32),
        ))
        .send_window(u64::from(tuning.send_window_mib).saturating_mul(MIB_U64))
        .send_fairness(false)
        .initial_rtt(Duration::from_millis(tuning.initial_rtt_ms))
        .max_idle_timeout(Some(
            IdleTimeout::try_from(Duration::from_secs(tuning.max_idle_timeout_secs))
                .expect("proxy max idle timeout fits quic varint"),
        ))
        .ack_frequency_config(Some(ack_frequency))
        .max_concurrent_bidi_streams(VarInt::from_u32(tuning.max_concurrent_streams))
        .max_concurrent_uni_streams(VarInt::from_u32(tuning.max_concurrent_streams));
}

pub(crate) fn proxy_quic_tuning_snapshot() -> ProxyQuicTuning {
    proxy_quic_tuning()
}

fn proxy_quic_tuning() -> ProxyQuicTuning {
    let mut tuning = proxy_quic_tuning_from_resources(
        available_parallelism_count(),
        memory_limit_mib(),
        open_file_soft_limit(),
    );
    tuning.stream_receive_window_mib = env_u32_mib(
        "KELI_CORE_QUIC_STREAM_WINDOW_MIB",
        tuning.stream_receive_window_mib,
        1,
        64,
    );
    tuning.receive_window_mib = env_u32_mib(
        "KELI_CORE_QUIC_CONN_WINDOW_MIB",
        tuning.receive_window_mib,
        tuning.stream_receive_window_mib.max(1),
        256,
    );
    tuning.send_window_mib = env_u32_mib(
        "KELI_CORE_QUIC_SEND_WINDOW_MIB",
        tuning.send_window_mib,
        tuning.stream_receive_window_mib.max(1),
        256,
    );
    tuning.max_concurrent_streams = env_u32(
        "KELI_CORE_QUIC_MAX_STREAMS",
        tuning.max_concurrent_streams,
        64,
        4096,
    );
    tuning.udp_socket_buffer_mib = env_usize(
        "KELI_CORE_QUIC_UDP_SOCKET_BUFFER_MIB",
        tuning.udp_socket_buffer_mib,
        1,
        64,
    );
    tuning.ack_eliciting_threshold = env_u32(
        "KELI_CORE_QUIC_ACK_THRESHOLD",
        tuning.ack_eliciting_threshold,
        1,
        64,
    );
    tuning.ack_max_delay_ms = env_u64(
        "KELI_CORE_QUIC_ACK_DELAY_MS",
        tuning.ack_max_delay_ms,
        1,
        100,
    );
    tuning.initial_rtt_ms = env_u64(
        "KELI_CORE_QUIC_INITIAL_RTT_MS",
        tuning.initial_rtt_ms,
        5,
        500,
    );
    tuning.max_idle_timeout_secs = env_u64(
        "KELI_CORE_QUIC_MAX_IDLE_SECS",
        tuning.max_idle_timeout_secs,
        5,
        300,
    );
    tuning
}

fn proxy_quic_tuning_from_resources(
    cpu_count: usize,
    memory_limit_mib: Option<usize>,
    fd_limit: Option<usize>,
) -> ProxyQuicTuning {
    let constrained_memory = memory_limit_mib.is_some_and(|mib| mib <= 1024);
    let constrained_fd = fd_limit.is_some_and(|limit| limit <= 8192);
    if constrained_memory || constrained_fd {
        return ProxyQuicTuning {
            stream_receive_window_mib: 4,
            receive_window_mib: 10,
            send_window_mib: 10,
            max_concurrent_streams: 256,
            udp_socket_buffer_mib: 2,
            ack_eliciting_threshold: DEFAULT_PROXY_ACK_ELICITING_THRESHOLD,
            ack_max_delay_ms: DEFAULT_PROXY_ACK_MAX_DELAY_MS,
            initial_rtt_ms: DEFAULT_PROXY_INITIAL_RTT_MS,
            max_idle_timeout_secs: DEFAULT_PROXY_MAX_IDLE_TIMEOUT_SECS,
        };
    }

    let max_concurrent_streams = if cpu_count <= 4 {
        256
    } else if cpu_count <= 8 {
        512
    } else {
        DEFAULT_PROXY_MAX_CONCURRENT_STREAMS
    };

    ProxyQuicTuning {
        stream_receive_window_mib: DEFAULT_PROXY_STREAM_RECEIVE_WINDOW_MIB,
        receive_window_mib: DEFAULT_PROXY_RECEIVE_WINDOW_MIB,
        send_window_mib: DEFAULT_PROXY_RECEIVE_WINDOW_MIB,
        max_concurrent_streams,
        udp_socket_buffer_mib: DEFAULT_PROXY_UDP_SOCKET_BUFFER_MIB,
        ack_eliciting_threshold: DEFAULT_PROXY_ACK_ELICITING_THRESHOLD,
        ack_max_delay_ms: DEFAULT_PROXY_ACK_MAX_DELAY_MS,
        initial_rtt_ms: DEFAULT_PROXY_INITIAL_RTT_MS,
        max_idle_timeout_secs: DEFAULT_PROXY_MAX_IDLE_TIMEOUT_SECS,
    }
}

fn env_u32_mib(name: &str, default_value: u32, min: u32, max: u32) -> u32 {
    env_u32(name, default_value, min, max)
}

fn env_u32(name: &str, default_value: u32, min: u32, max: u32) -> u32 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default_value)
}

fn env_u64(name: &str, default_value: u64, min: u64, max: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default_value)
}

fn env_usize(name: &str, default_value: usize, min: usize, max: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|value| value.clamp(min, max))
        .unwrap_or(default_value)
}

pub(crate) fn apply_quic_congestion_control(
    transport: &mut quinn::TransportConfig,
    value: &str,
    default_value: &str,
    context: &str,
) -> io::Result<()> {
    let selected = select_quic_congestion_control(value, default_value);
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

fn select_quic_congestion_control(value: &str, default_value: &str) -> String {
    let normalized = normalize_quic_congestion_control(value);
    if normalized.is_empty() {
        normalize_quic_congestion_control(default_value)
    } else {
        normalized
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_quic_defaults_use_low_initial_rtt_for_proxy_streams() {
        let mut transport = quinn::TransportConfig::default();

        apply_proxy_quic_transport_defaults(&mut transport);

        let debug = format!("{transport:?}");
        let tuning = proxy_quic_tuning_snapshot();
        assert!(debug.contains(&format!(
            "stream_receive_window: {}",
            tuning.stream_receive_window_mib.saturating_mul(MIB_U32)
        )));
        assert!(debug.contains(&format!(
            "receive_window: {}",
            tuning.receive_window_mib.saturating_mul(MIB_U32)
        )));
        assert!(debug.contains(&format!(
            "send_window: {}",
            u64::from(tuning.send_window_mib).saturating_mul(MIB_U64)
        )));
        assert!(debug.contains(&format!("initial_rtt: {}ms", tuning.initial_rtt_ms)));
        assert!(debug.contains(&format!(
            "max_idle_timeout: Some({})",
            tuning.max_idle_timeout_secs.saturating_mul(1000)
        )));
        assert!(debug.contains("mtu_discovery_config: Some"));
        assert!(debug.contains("send_fairness: false"));
        assert!(debug.contains("ack_frequency_config: Some"));
        assert!(debug.contains(&format!(
            "max_concurrent_bidi_streams: {}",
            tuning.max_concurrent_streams
        )));
        assert!(debug.contains(&format!(
            "max_concurrent_uni_streams: {}",
            tuning.max_concurrent_streams
        )));
    }

    #[test]
    fn proxy_quic_tuning_scales_down_on_small_machines() {
        let tuning = proxy_quic_tuning_from_resources(2, Some(1024), Some(8192));

        assert_eq!(tuning.stream_receive_window_mib, 4);
        assert_eq!(tuning.receive_window_mib, 10);
        assert_eq!(tuning.send_window_mib, 10);
        assert_eq!(tuning.max_concurrent_streams, 256);
        assert_eq!(tuning.udp_socket_buffer_mib, 2);
    }

    #[test]
    fn proxy_quic_tuning_keeps_official_defaults_on_normal_nodes() {
        let low_cpu = proxy_quic_tuning_from_resources(2, Some(64_000), Some(1_000_000));
        assert_eq!(low_cpu.stream_receive_window_mib, 8);
        assert_eq!(low_cpu.receive_window_mib, 20);
        assert_eq!(low_cpu.max_concurrent_streams, 256);

        let mid_memory = proxy_quic_tuning_from_resources(8, Some(4096), Some(1_000_000));
        assert_eq!(mid_memory.stream_receive_window_mib, 8);
        assert_eq!(mid_memory.receive_window_mib, 20);
        assert_eq!(mid_memory.max_concurrent_streams, 512);
    }

    #[test]
    fn proxy_quic_tuning_keeps_hy2_style_defaults_on_capable_machines() {
        let tuning = proxy_quic_tuning_from_resources(16, Some(16_384), Some(1_000_000));

        assert_eq!(tuning.stream_receive_window_mib, 8);
        assert_eq!(tuning.receive_window_mib, 20);
        assert_eq!(tuning.send_window_mib, 20);
        assert_eq!(tuning.max_concurrent_streams, 1024);
        assert_eq!(tuning.max_idle_timeout_secs, 30);
    }

    #[test]
    fn empty_quic_congestion_control_uses_normalized_default() {
        assert_eq!(select_quic_congestion_control("", "bbr"), "bbr");
        assert_eq!(select_quic_congestion_control(" ", "new-reno"), "new_reno");
        assert_eq!(select_quic_congestion_control("reno", "bbr"), "reno");
    }
}
