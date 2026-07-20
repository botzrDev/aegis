//! Pure HTTP allow-check helpers shared by sandbox and runtime.
//!
//! These are stateless predicates — no I/O, no cap-std, no wasmtime.
//! Both `botzr-aegis-sandbox` (WIT host imports) and `botzr-aegis-runtime`
//! (`HostEffectContext`) call the same functions so the allow logic lives
//! in one place.

use crate::CapabilityGrant;

/// Extract the host portion from an `http(s)://host/...` URL (no IDNA).
pub fn parse_http_host(url: &str) -> Option<String> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))?;
    let host = rest.split(['/', '?', '#']).next()?;
    let host = host.split(':').next()?;
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Check whether `url` is allowed by the grant's NetGrant for HTTP GET.
///
/// Returns `Ok(())` if the host is in the grant's allow-list with a GET method
/// entry. Returns `Err(reason)` with a descriptive reason otherwise.
pub fn http_get_allowed(grant: &CapabilityGrant, url: &str) -> Result<(), String> {
    let host = parse_http_host(url).ok_or_else(|| "malformed url".to_string())?;
    let net = grant
        .net
        .as_ref()
        .ok_or_else(|| "network denied: no net grant".to_string())?;
    let allowed = net.http.iter().any(|entry| {
        entry.host == host && entry.methods.iter().any(|m| m.eq_ignore_ascii_case("GET"))
    });
    if !allowed {
        return Err(format!("network denied: host {host} not in grant"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityGrant, HttpGrant, NetGrant, ToolId};

    fn allow_get(host: &str) -> NetGrant {
        NetGrant {
            http: vec![HttpGrant {
                host: host.into(),
                ports: vec![443],
                methods: vec!["GET".into()],
            }],
        }
    }

    fn grant_with_net(net: Option<NetGrant>) -> CapabilityGrant {
        CapabilityGrant {
            grant_id: "g1".into(),
            tool_id: ToolId::new("test"),
            fs: None,
            net,
            max_memory_bytes: 1 << 20,
            max_wall_ms: 1_000,
            max_output_bytes: 1 << 20,
        }
    }

    #[test]
    fn parse_http_host_extracts_authority() {
        assert_eq!(
            parse_http_host("https://Example.COM/path"),
            Some("example.com".into())
        );
        assert_eq!(parse_http_host("not-a-url"), None);
    }

    #[test]
    fn http_get_allowed_without_net_grant_denies() {
        let grant = grant_with_net(None);
        let err = http_get_allowed(&grant, "https://api.example.com/data").unwrap_err();
        assert!(err.contains("no net grant"), "{err}");
    }

    #[test]
    fn http_get_allowed_host_outside_allowlist_denies() {
        let grant = grant_with_net(Some(allow_get("api.example.com")));
        let err = http_get_allowed(&grant, "https://evil.example.com/exfil").unwrap_err();
        assert!(err.contains("not in grant"), "{err}");
    }

    #[test]
    fn http_get_allowed_malformed_url_denies() {
        let grant = grant_with_net(Some(allow_get("api.example.com")));
        let err = http_get_allowed(&grant, "ftp://api.example.com/x").unwrap_err();
        assert!(err.contains("malformed url"), "{err}");
    }

    #[test]
    fn http_get_allowed_allowed_host_passes() {
        let grant = grant_with_net(Some(allow_get("api.example.com")));
        http_get_allowed(&grant, "https://api.example.com/data").unwrap();
    }
}
