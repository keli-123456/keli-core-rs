use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) fn emit_legacy_line(line: &str) {
    eprintln!("{}", format_legacy_log_line(line));
}

fn format_legacy_log_line(line: &str) -> String {
    format_legacy_log_line_at(line, unix_now())
}

fn format_legacy_log_line_at(line: &str, unix_secs: u64) -> String {
    let (level, component, message) = parse_legacy_log_line(line);
    format!(
        "[{level}] {} {component} {message}",
        format_timestamp(unix_secs)
    )
}

fn parse_legacy_log_line(line: &str) -> (&str, &str, &str) {
    let line = line.trim();
    let Some((level, rest)) = split_token(line) else {
        return ("INFO", "core", line);
    };
    if !is_log_level(level) {
        return ("INFO", "core", line);
    }
    let Some((component, message)) = split_token(rest) else {
        return (level, "core", rest.trim());
    };
    (level, component, message.trim())
}

fn is_log_level(value: &str) -> bool {
    matches!(value, "DEBUG" | "INFO" | "WARN" | "ERROR")
}

fn split_token(value: &str) -> Option<(&str, &str)> {
    let value = value.trim_start();
    let split = value
        .char_indices()
        .find_map(|(index, character)| character.is_ascii_whitespace().then_some(index))?;
    Some((&value[..split], &value[split..]))
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

fn format_timestamp(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let seconds = unix_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}/{month:02}/{day:02} {hour:02}:{minute:02}:{second:02}")
}

fn civil_from_days(days_since_epoch: i64) -> (i32, u32, u32) {
    let z = days_since_epoch + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = mp + if mp < 10 { 3 } else { -9 };
    if month <= 2 {
        year += 1;
    }
    (year as i32, month as u32, day as u32)
}

#[cfg(test)]
mod tests {
    use super::{format_legacy_log_line_at, format_timestamp};

    #[test]
    fn formats_core_legacy_log_line_with_timestamp() {
        assert_eq!(
            format_legacy_log_line_at(
                "INFO  core   trojan relay finished node_tag=node target=talk.google.com:5228",
                1_591_947_416,
            ),
            "[INFO] 2020/06/12 07:36:56 core trojan relay finished node_tag=node target=talk.google.com:5228"
        );
    }

    #[test]
    fn defaults_unstructured_core_lines_to_info() {
        assert_eq!(
            format_legacy_log_line_at("trojan relay finished", 0),
            "[INFO] 1970/01/01 00:00:00 core trojan relay finished"
        );
    }

    #[test]
    fn formats_timestamp() {
        assert_eq!(format_timestamp(1_591_947_416), "2020/06/12 07:36:56");
    }
}
