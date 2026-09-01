//! Pure HTTP allow-check helpers shared by sandbox and runtime.
//!
//! These are stateless predicates — no I/O, no cap-std, no wasmtime.
//! Both `botzr-aegis-sandbox` (WIT host imports) and `botzr-aegis-runtime`
//! (`HostEffectContext`) call the same functions so the allow logic lives
//! in one place.

use crate::CapabilityGrant;

/// Extract the host portion from an `http(s)://host/...` URL (no IDNA).
///
/// Host only: the port is discarded. [`parse_http_authority`] is the port-aware
/// sibling, and it is what the allow-check uses; this one stays as published for
/// callers outside this repository.
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

/// Extract the host **and port** from an `http(s)://host[:port]/...` URL.
///
/// The scheme supplies the default — 443 for `https`, 80 for `http` — and an
/// explicit port always wins, including an explicit `:443`. The host is
/// lowercased, matching [`parse_http_host`]; a test pins the two to the same
/// host answer, because two parsers that disagree about the host are worse than
/// one that ignores the port.
///
/// **Fails closed to `None` rather than guessing.** A non-`http(s)` scheme, an
/// empty host, an empty or non-`u16` port, and an authority carrying userinfo
/// all return `None`, which the caller turns into a denial. Userinfo is the
/// one worth naming: in `https://api.example.com:8443@evil.com/x` the authority
/// is `evil.com`, and a parser that reached for `:` before `@` would answer with
/// the allow-listed name instead — so this refuses the URL rather than parse a
/// form it does not implement. Bracketed IPv6 literals are refused by the same
/// rule; this parser does not implement them.
pub fn parse_http_authority(url: &str) -> Option<(String, u16)> {
    let (rest, default_port) = match url.strip_prefix("https://") {
        Some(rest) => (rest, 443u16),
        None => (url.strip_prefix("http://")?, 80u16),
    };
    let authority = rest.split(['/', '?', '#']).next()?;
    if authority.contains('@') {
        return None;
    }
    let (host, port) = match authority.split_once(':') {
        // An empty or out-of-range port parses as `None` here, which is the
        // fail-closed answer — never the scheme default, or `:99999` would
        // silently become 443.
        Some((host, port)) => (host, port.parse::<u16>().ok()?),
        None => (authority, default_port),
    };
    if host.is_empty() {
        return None;
    }
    Some((host.to_ascii_lowercase(), port))
}

/// Check whether `url` is allowed by the grant's NetGrant for HTTP GET.
///
/// **Three axes, all read from the grant: host, method and port.** The port
/// comes from the URL's authority, defaulting to the scheme's port when the URL
/// names none — so a grant listing only 443 refuses `https://host:8080/` even
/// though the host matches. Before this checked the port, `HttpGrant.ports` was
/// validated at mint, subset-checked when narrowing, and recorded as the `net`
/// decision axis in the signed record, while no enforcement path read it: the
/// record asserted a dimension the enforcement layer did not have (ADR-0007).
///
/// `Err(reason)` names **which axis refused**, and the host and port reasons are
/// deliberately lexically disjoint. A caller that cannot tell them apart cannot
/// tell a typo in an allow-list from an attempt to reach an unlisted service on
/// a permitted host.
///
/// **The effect behind this is still a stub.** No network I/O happens in the v1
/// slice, so this is enforcement staged ahead of the effect rather than a check
/// on a live request.
pub fn http_get_allowed(grant: &CapabilityGrant, url: &str) -> Result<(), String> {
    let (host, port) = parse_http_authority(url).ok_or_else(|| "malformed url".to_string())?;
    let net = grant
        .net
        .as_ref()
        .ok_or_else(|| "network denied: no net grant".to_string())?;
    // Two stages rather than one `any()` over all three axes: folding the port
    // in would report an allow-listed host with the host-denial phrase, and
    // assertions elsewhere in the tree read that phrase as a host-denial
    // marker. A host that matches nothing reports the host; a host that matches
    // on the wrong port reports the port. The two reasons are kept lexically
    // disjoint for that reason, and the tests below pin both in full.
    let mut host_matched = false;
    for entry in &net.http {
        let method_ok = entry.methods.iter().any(|m| m.eq_ignore_ascii_case("GET"));
        if entry.host != host || !method_ok {
            continue;
        }
        host_matched = true;
        if entry.ports.contains(&port) {
            return Ok(());
        }
    }
    if !host_matched {
        return Err(format!("network denied: host {host} not in grant"));
    }
    Err(format!(
        "network denied: port {port} not allowed for host {host}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CapabilityGrant, HttpGrant, NetGrant, ToolId};

    fn allow_get_on_port(host: &str, port: u16) -> NetGrant {
        NetGrant {
            http: vec![HttpGrant {
                host: host.into(),
                ports: vec![port],
                methods: vec!["GET".into()],
            }],
        }
    }

    fn allow_get(host: &str) -> NetGrant {
        allow_get_on_port(host, 443)
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

    #[test]
    fn parse_http_authority_takes_the_default_port_from_the_scheme() {
        assert_eq!(
            parse_http_authority("https://host/path"),
            Some(("host".into(), 443))
        );
        assert_eq!(
            parse_http_authority("http://host/path"),
            Some(("host".into(), 80))
        );
        // No path, and query/fragment terminators, all end the authority.
        assert_eq!(
            parse_http_authority("https://host"),
            Some(("host".into(), 443))
        );
        assert_eq!(
            parse_http_authority("https://host?q=1"),
            Some(("host".into(), 443))
        );
    }

    #[test]
    fn parse_http_authority_prefers_an_explicit_port() {
        assert_eq!(
            parse_http_authority("https://host:8443/path"),
            Some(("host".into(), 8443))
        );
        // Explicit and equal to the default is still explicit — the two paths
        // must agree, or a grant listing 443 would depend on how the URL was
        // spelled.
        assert_eq!(
            parse_http_authority("https://host:443/path"),
            Some(("host".into(), 443))
        );
        // An explicit port on the http scheme does not inherit 80.
        assert_eq!(
            parse_http_authority("http://host:8080/path"),
            Some(("host".into(), 8080))
        );
    }

    #[test]
    fn parse_http_authority_lowercases_the_host() {
        assert_eq!(
            parse_http_authority("https://Example.COM:8443/path"),
            Some(("example.com".into(), 8443))
        );
    }

    #[test]
    fn parse_http_authority_fails_closed() {
        // Not a guess, a refusal: every one of these returns None, and the
        // caller turns None into `malformed url` rather than reaching for the
        // scheme default.
        for url in [
            "ftp://host/x",         // not an http(s) scheme
            "not-a-url",            // no scheme at all
            "https:///x",           // empty host
            "https://:443/x",       // empty host with a port
            "https://host:abc/x",   // port is not a number
            "https://host:99999/x", // port is out of u16 range
            "https://host:-1/x",    // negative port
            "https://host:/x",      // empty port
            "https://user@host/x",  // userinfo, unparsed
        ] {
            assert_eq!(parse_http_authority(url), None, "{url} must fail closed");
        }
    }

    #[test]
    fn parse_http_authority_refuses_a_userinfo_authority() {
        // The reason the `@` guard exists. `parse_http_host` reaches for `:`
        // before `@` and answers `api.example.com` here, while the authority
        // the request would actually reach is `evil.com` — so a grant for
        // `api.example.com` would admit it. This parser refuses the form it
        // does not implement instead of guessing which side is the host.
        let sneaky = "https://api.example.com:8443@evil.com/x";
        assert_eq!(parse_http_host(sneaky), Some("api.example.com".into()));
        assert_eq!(parse_http_authority(sneaky), None);

        let grant = grant_with_net(Some(allow_get("api.example.com")));
        let err = http_get_allowed(&grant, sneaky).unwrap_err();
        assert!(err.contains("malformed url"), "{err}");
    }

    #[test]
    fn parse_http_authority_and_parse_http_host_agree_on_the_host() {
        // The two parsers are deliberately separate: `parse_http_host` is
        // published API and its behaviour is frozen. This is what stops them
        // drifting apart on the half they share.
        for url in [
            "https://api.example.com/data",
            "https://api.example.com:8443/data",
            "http://Example.COM/path",
            "https://host",
        ] {
            let (authority_host, _) = parse_http_authority(url).expect("well-formed");
            assert_eq!(
                Some(authority_host),
                parse_http_host(url),
                "parsers disagree on the host of {url}"
            );
        }
    }

    #[test]
    fn http_get_allowed_port_outside_grant_denies() {
        let grant = grant_with_net(Some(allow_get("api.example.com")));
        let err = http_get_allowed(&grant, "https://api.example.com:8080/data").unwrap_err();
        // Pinned in full rather than by substring. The port reason has to stay
        // lexically disjoint from the host reason — assertions across this
        // workspace read the host phrase as a host-denial marker, and a port
        // denial that reused it would make every one of them pass on the wrong
        // finding. An equality assertion proves the disjointness outright,
        // where `!contains(...)` would only test for one spelling of it.
        assert_eq!(
            err,
            "network denied: port 8080 not allowed for host api.example.com"
        );
    }

    #[test]
    fn http_get_allowed_listed_port_passes() {
        let grant = grant_with_net(Some(allow_get_on_port("api.example.com", 8080)));
        http_get_allowed(&grant, "https://api.example.com:8080/data").unwrap();
        // ...and the same grant refuses the scheme default, which is what
        // proves the port is read from the URL rather than assumed.
        let err = http_get_allowed(&grant, "https://api.example.com/data").unwrap_err();
        assert!(err.contains("port 443"), "{err}");
    }

    #[test]
    fn http_get_allowed_unknown_host_reports_the_host_not_the_port() {
        // Ordering matters: an unlisted host on an unlisted port must report
        // the host. Reporting the port would tell an operator the allow-list
        // contains a host it does not.
        let grant = grant_with_net(Some(allow_get("api.example.com")));
        let err = http_get_allowed(&grant, "https://evil.example.com:8080/exfil").unwrap_err();
        // Pinned in full, like the port cases: this is a genuine fifth
        // host-denial assertion, not a port denial wearing the host phrase.
        assert_eq!(err, "network denied: host evil.example.com not in grant");
    }
}
