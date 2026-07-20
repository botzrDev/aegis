//! Model B host import stubs — enforce the grant before any effect.
//!
//! v1 slice: log is a no-op sink; http always denies unless the grant carries
//! a matching host entry (no real network I/O in this slice).
//!
//! HTTP allow-check logic is shared with `botzr-aegis-runtime` via
//! `botzr-aegis-core::http_check` — one source of truth for "is this GET
//! host allowed?".

use botzr_aegis_core::http_get_allowed;

use crate::bindings::aegis::host::http::{self, Deny, Response};
use crate::bindings::aegis::host::log::{self, Level};
use crate::bindings::aegis::tool::tool_types;
use crate::state::ToolState;

/// Maximum log message size enforced host-side (bytes).
const MAX_LOG_MESSAGE_BYTES: usize = 4096;

impl tool_types::Host for ToolState {}

impl log::Host for ToolState {
    async fn emit(&mut self, level: Level, message: String) {
        if message.len() > MAX_LOG_MESSAGE_BYTES {
            // v1: oversize messages are dropped host-side; rate caps land with AEG-11.
            let _ = (level, message);
            return;
        }
        // v1: no sink wired — grant is checked implicitly (any registered tool
        // may emit). Never log secrets.
        let _ = (level, message);
    }
}

impl http::Host for ToolState {
    async fn get(&mut self, url: String) -> Result<Response, Deny> {
        // Shared allow-check from core — same logic as HostEffectContext::http_get.
        http_get_allowed(self.grant(), &url).map_err(|reason| Deny { reason })?;

        // v1: no real network — grant check passed, effect is stubbed.
        Err(Deny {
            reason: "http host stub: no network in v1 slice".into(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use botzr_aegis_core::{CapabilityGrant, NetGrant, ToolId};
    use http::Host as _;
    use wasmtime_wasi::WasiCtxBuilder;

    fn state_with_net(net: Option<NetGrant>) -> ToolState {
        let grant = CapabilityGrant {
            grant_id: "g1".into(),
            tool_id: ToolId::new("net-tool"),
            fs: None,
            net,
            max_memory_bytes: 1 << 20,
            max_wall_ms: 1_000,
            max_output_bytes: 1 << 20,
        };
        ToolState::new(WasiCtxBuilder::new().build(), grant)
    }

    fn allow_get(host: &str) -> NetGrant {
        NetGrant {
            http: vec![botzr_aegis_core::HttpGrant {
                host: host.into(),
                ports: vec![443],
                methods: vec!["GET".into()],
            }],
        }
    }

    #[tokio::test]
    async fn http_get_denies_without_net_grant() {
        let mut state = state_with_net(None);
        let deny = state
            .get("https://api.example.com/data".into())
            .await
            .expect_err("no net grant must deny");
        assert!(deny.reason.contains("no net grant"), "{}", deny.reason);
    }

    #[tokio::test]
    async fn http_get_denies_host_outside_allowlist() {
        let mut state = state_with_net(Some(allow_get("api.example.com")));
        let deny = state
            .get("https://evil.example.com/exfil".into())
            .await
            .expect_err("host outside the allow-list must deny");
        assert!(deny.reason.contains("not in grant"), "{}", deny.reason);
    }

    #[tokio::test]
    async fn http_get_denies_malformed_url() {
        let mut state = state_with_net(Some(allow_get("api.example.com")));
        let deny = state
            .get("ftp://api.example.com/x".into())
            .await
            .expect_err("non-http scheme must deny");
        assert!(deny.reason.contains("malformed url"), "{}", deny.reason);
    }

    #[tokio::test]
    async fn http_get_passes_grant_check_then_stubs_effect() {
        // An allow-listed host clears the grant check; the effect is still a
        // no-network stub in the v1 slice. This proves the grant gate is what
        // denies unlisted hosts, not a blanket "http is off".
        let mut state = state_with_net(Some(allow_get("api.example.com")));
        let deny = state
            .get("https://api.example.com/data".into())
            .await
            .expect_err("v1 slice performs no real network I/O");
        assert!(
            deny.reason.contains("no network in v1 slice"),
            "{}",
            deny.reason
        );
    }
}
