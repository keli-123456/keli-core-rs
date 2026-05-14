use std::io;
use std::sync::Arc;

use quinn::VarInt;

const PROXY_STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const PROXY_RECEIVE_WINDOW: u32 = 32 * 1024 * 1024;
const PROXY_SEND_WINDOW: u64 = 32 * 1024 * 1024;
const PROXY_MAX_CONCURRENT_STREAMS: u32 = 1024;

pub(crate) fn apply_proxy_quic_transport_defaults(transport: &mut quinn::TransportConfig) {
    transport
        .stream_receive_window(VarInt::from_u32(PROXY_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(PROXY_RECEIVE_WINDOW))
        .send_window(PROXY_SEND_WINDOW)
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
