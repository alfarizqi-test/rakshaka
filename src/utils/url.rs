use std::net::IpAddr;
use url::Url;

/// Returns `true` if the host is a blocked/private/internal address that
/// must never be fetched by the server (SSRF prevention).
pub fn is_blocked_host(host: &str) -> bool {
    let host = host.trim().to_lowercase();

    // -- Explicit name blocklist --
    let blocked_names = [
        "localhost",
        "broadcasthost",
        "ip6-localhost",
        "ip6-loopback",
        "ip6-allnodes",
        "ip6-allrouters",
        "metadata.google.internal", // GCP metadata
        "169.254.169.254",           // AWS/cloud metadata
        "100.100.100.200",           // Alibaba cloud metadata
    ];
    if blocked_names.contains(&host.as_str()) {
        return true;
    }

    // -- Internal TLD patterns --
    if host.ends_with(".local")
        || host.ends_with(".internal")
        || host.ends_with(".localhost")
        || host.ends_with(".corp")
        || host.ends_with(".home")
        || host.ends_with(".lan")
        || host.ends_with(".intranet")
    {
        return true;
    }

    // -- IP address range checks --
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_blocked_ip(ip);
    }

    false
}

fn is_blocked_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 127.0.0.0/8  — loopback
            if octets[0] == 127 {
                return true;
            }
            // 0.0.0.0
            if v4.is_unspecified() {
                return true;
            }
            // 10.0.0.0/8   — private Class A
            if octets[0] == 10 {
                return true;
            }
            // 172.16.0.0/12 — private Class B
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // 192.168.0.0/16 — private Class C
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 169.254.0.0/16 — link-local / cloud metadata
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // 100.64.0.0/10  — shared address space (CGN)
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return true;
            }
            false
        }
        IpAddr::V6(v6) => {
            // ::1 loopback, ::, fc00::/7 (ULA), fe80::/10 (link-local)
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // ULA: fc00::/7
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // link-local: fe80::/10
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Extract the hostname from a URL string for SSRF validation.
/// Returns `None` if the URL cannot be parsed or has no host.
pub fn extract_host(raw_url: &str) -> Option<String> {
    Url::parse(raw_url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_lowercase()))
}
