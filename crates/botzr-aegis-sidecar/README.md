# botzr-aegis-sidecar

Phase 2 sidecar gateway for Aegis — UDS gRPC/HTTP (not yet implemented).

The sidecar will expose the Aegis runtime over a Unix-domain socket so that agent frameworks can make tool-call requests without linking the full Aegis crate graph.

## Status

Not implemented. Placed in the workspace to reserve the crate name and publish the interface contract early.

## Dependencies

- `botzr-aegis-runtime` (will be used when implemented)
