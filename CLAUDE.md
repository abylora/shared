# shared

<!-- Only what deviates from the workspace root. The root CLAUDE.md and docs/ are
     already loaded in every session here. -->

## What this is

A Go module of code that more than one service must agree on — currently the transport
implementations, later the wire types for the relay list and key set. It is a
**library, not a service**: nothing runs it on its own.

It exists because a transport is a *protocol* between the node and the client, not a
utility. If each side grew its own Shadowsocks or QUIC implementation they would drift,
and the failure would surface as unexplained dropped tunnels. One implementation, both
sides consume it. It cannot live inside either consumer, because neither should depend
on the other.

## Deviations

- **An interface change here is a breaking change for every consumer** — the node agent
  and all four clients. Changing an exported signature is not a local decision: escalate
  to `abylora-master` before planning one.
- **No dependency on wireguard-go.** The `Conn` abstraction is deliberately narrower
  than WireGuard's own `conn.Bind` — a connected datagram pipe to exactly one relay —
  so that the node agent, which drives the kernel module through wgctrl, does not
  inherit a userspace WireGuard implementation it will never use. Adapting to
  `conn.Bind` is a thin shim on the client side, and it belongs there.
- **Transport kind strings are wire contract.** The values of `transport.Kind` appear
  verbatim in the signed relay list. Renaming one breaks deployed clients.
- No domain modelling here. There are no aggregates, entities or repositories in a
  transport library; see `docs/engineering.md`.
