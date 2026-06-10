# WHOIS (RFC 3912) Protocol Analyzer

Spicy-based WHOIS (RFC 3912) protocol analyzer for [Zeek](https://zeek.org).

## Detailed Description

WHOIS is a basic TCP request/response protocol: client sends one query line, server returns free-form text and closes. 

This analyzer employs intelligent interpretation to both halves of the exchange, formulating a structured `whois.log`.
It classifies the **query** as `domain`, `ipv4`, `ipv6`, or `asn`, then reads the **reply** (capped at 64 KB) and scans it for registry/RIR fields: `owner`, `status`, `origin AS`, `registration`, `update` and expiry dates, name servers, abuse contact.

## Features

- Logs WHOIS queries and structured reply metadata to `whois.log`
- Dynamic protocol detection (DPD) via bidirectional signatures
- Reply time tracking (request-to-reply delta)
- Weirds for protocol anomalies (empty requests, unusually large queries)
- UTF-8/IDN support (tested against JP, CN, KR WHOIS servers)

## Detection use cases (examples)

- **Sinkhole / seizure** — `status` of `serverHold` or `clientHold` marks a domain the registry has frozen.
- **Routing intelligence** — `origin_as` on a network query is the BGP-filter input; flag route objects whose origin AS doesn't match expected peering.
- **Fresh infrastructure** — a `registered` date inside your lookback window flags newly-stood-up domains; a short `registry_expiry` (1-year registration) sharpens the signal.
- **Infrastructure pivot** — `name_server` ties a domain to its DNS hosting; pivot to related domains sharing a name server.

## Requires

- Zeek 6.1.0 (bundled with Spicy 1.9.0) minimum
- C++ toolchain and libpcap headers are required to build the analyzer:
  * `gcc g++ make cmake libpcap-dev`
  * As with any zkg Spicy analyzer, the code is Spicy source and compiled at install time
  * NOTE: The official [`zeek/zeek` container image](https://hub.docker.com/r/zeek/zeek) omits these, so install first or the build will fail with `pcap.h: No such file or directory`

## Install

[zkg](https://docs.zeek.org/projects/package-manager/) package, from [Zeek Package Source](https://github.com/zeek/packages):

```bash
zkg install spicy-whois
```

## Events

```zeek
event WHOIS::request(c: connection, is_orig: bool, query: string)
```

Raised for each client query, with `query` holding the string stripped of its line terminator.

```zeek
event WHOIS::reply(c: connection, is_orig: bool, data: string)
```

Raised once per reply, with `data` holding the full server text (read until close, capped at 64 KB).

Where the events above hand back raw bytes, `WHOIS::log_whois(rec: WHOIS::Info)` is where the analyzer interpretation executes: once per connection it emits the assembled `WHOIS::Info` record — query classified, reply fields extracted — that is written to `whois.log`.  
See [WHOIS answer schema](#whois-answer-schema) for fields.

## Example output

Run with testing pcap, pretty-print `whois.log` with `jq`:

```bash
zeek -C -r testing/Traces/whois-domain.pcap whois.hlto scripts/__load__.zeek LogAscii::use_json=T
jq --color-output . whois.log
```

**domain** lookup (`whois-domain.pcap`) — registrar, EPP `status` codes, name servers, abuse contact:

```json
{
  "ts": 1779334478.346291,
  "uid": "Cm3FuO2WPLUSPqUolb",
  "id.orig_h": "192.168.1.231",
  "id.orig_p": 63154,
  "id.resp_h": "192.34.234.30",
  "id.resp_p": 43,
  "query": "domain cloudflare.com",
  "query_type": "domain",
  "resource": "CLOUDFLARE.COM",
  "owner": "Cloudflare, Inc.",
  "registered": "2009-02-17T22:07:54Z",
  "updated": "2024-01-09T16:45:28Z",
  "registry_expiry": "2033-02-17T22:07:54Z",
  "name_server": [
    "ns3.cloudflare.com",
    "ns4.cloudflare.com",
    "ns5.cloudflare.com",
    "ns6.cloudflare.com",
    "ns7.cloudflare.com"
  ],
  "status": [
    "clientDeleteProhibited https://icann.org/epp#clientDeleteProhibited",
    "clientTransferProhibited https://icann.org/epp#clientTransferProhibited",
    "clientUpdateProhibited https://icann.org/epp#clientUpdateProhibited",
    "serverDeleteProhibited https://icann.org/epp#serverDeleteProhibited",
    "serverTransferProhibited https://icann.org/epp#serverTransferProhibited",
    "serverUpdateProhibited https://icann.org/epp#serverUpdateProhibited"
  ],
  "abuse_contact": "registrar-abuse@cloudflare.com",
  "reply_time": 0.025169849395751953,
  "reply_size": 3719
}
```

**network** lookup (`whois-net.pcap`) — the same record shape pivoted on `query_type`, here an RIR `inetnum` with `server_name` and `origin_as` populated and the domain-only fields absent:

```json
{
  "ts": 1779334777.802331,
  "uid": "CBdloO3gjjCrOi6Q5l",
  "id.orig_h": "192.168.1.231",
  "id.orig_p": 64829,
  "id.resp_h": "193.0.6.135",
  "id.resp_p": 43,
  "query": "95.217.0.1",
  "query_type": "ipv4",
  "server_name": "RIPE",
  "resource": "95.217.0.0 - 95.217.15.255",
  "owner": "ORG-HOA1-RIPE",
  "origin_as": "AS24940",
  "registered": "2023-12-12T12:40:45Z",
  "updated": "2023-12-12T12:40:45Z",
  "status": [
    "ASSIGNED PA"
  ],
  "reply_time": 0.16294193267822266,
  "reply_size": 3800
}
```

## Analyzer: Attachment, confirmation, and ports

A connection is logged only after two steps: the analyzer **attaches** to it, then the parser **confirms** the bytes are WHOIS.

**Attach** happens on 43/tcp. `Analyzer::register_for_ports` binds the analyzer to that port, so every connection on 43/tcp gets the analyzer at connection start, before any payload is parsed.

**Confirm** happens in the parser, independently on each side. A query line that parses calls `spicy::accept_input()`; a reply that carries data does the same. Either alone confirms, so a client query with no reply still tags the connection. A parse failure on either side calls `zeek::reject_protocol()` instead.

Confirmation, not the port match, is what sets `service=whois` in `conn.log`. Non-WHOIS traffic on 43/tcp still gets the analyzer attached, but never confirms, so `service` stays empty.

The full path is **port → attach → parse → `accept_input()` confirms → `service=whois`.**

### DPD signature

The signature in [`scripts/dpd.sig`](scripts/dpd.sig) is a third, independent mechanism: a content-based attach path for non-standard ports.

WHOIS has no constant byte pattern or fixed-offset header to key against, so the signature pairs a client and server match tuned against the captured bytes in `testing/Traces/`. The server side fires only after the client query matches (`requires-reverse-signature`), avoiding false positives from other text protocols whose replies carry a stray keyword.

`tcp-state originator`/`responder` is used without `established`, matching core analyzers; payload exists only post-handshake, so `established` is redundant.

**Client (originator) — a single query line ending in CRLF:**

- Character class covers domain/IP/ASN chars plus flag punctuation (`- . @ = / + : ,`) and a literal space, so RIPE-style flag queries like `-T dn,ace example.de` match.
- **No `\s`** in the class. An earlier version included it, silently matching internal `\r`/`\n` — so multi-line payloads (`foo.com\r\nbar.com\r\n`) and bare CRLF floods registered as valid single queries. Dropping `\s` rejects them.
- Underscore is excluded: it let SSH banners (`SSH-2.0-libssh_…`) match.
- `\x80-\xff` is kept for IDN/CJK queries.

**Server (responder) — keyword match, gated by `requires-reverse-signature`:**

- Matches keywords present in real registry/registrar/RIR replies.
- Includes `route6?:` (not just `route:`) plus `origin:`/`source:`, closing a gap where IPv6 `route6:` objects from RIPE/RADB went undetected.

### WHOIS on a non-standard port

To parse WHOIS off 43/tcp, add the port so the analyzer attaches there at connection start, the same path it uses on 43/tcp:

```zeek
redef WHOIS::ports += { 4343/tcp };
```

## Parsing limits and bounds

Cutoff bounds protect against malformed / hostile traffic:

- **Request line** ([`whois.spicy`](analyzer/whois.spicy)) — printable bytes (`\x09`, `\x20`–`\x7e`, `\x80`–`\xff` for IDN), terminated by an optional CR and a required LF. An empty query raises `whois_empty_request`; a query over **512 bytes** raises `whois_oversized_request` (the line still parses — the weird is the signal).
- **Reply body** — read to close, capped at **64 KB** (`&size=65536 &eod`); the first 64 KB parse, bytes past the cap are discarded, so `reply_size` truncates.
- **Field extraction** ([`main.zeek`](scripts/main.zeek)) — reply split on LF, each line on its first `:`; keys lowercased, values stripped, empties skipped. Single-valued fields are **first-wins**; `status` and `name_server` accumulate into a set (`name_server` lowercased to dedup), bounded by the 64 KB cap.

## WHOIS answer schema

Answers come in two forms, both mapped into one set of generic fields pivoted on `query_type`:

- **domain** responses (registrar/registry data)
- **network** responses (RIR inetnum/route/ASN objects)

Always read a value alongside `query_type` — the same column carries different elements per type (`owner` is a registrar for a domain, an `mnt-by` maintainer for a network).

| Field | Domain response | Network response | Why it matters to a defender |
|-------|-----------------|------------------|------------------------------|
| `query` | the query string | the query string | What was looked up |
| `query_type` | `domain` | `ipv4` / `ipv6` / `asn` | Split registrar lookups from routing-intel lookups |
| `server_name` | — | source registry (RIPE, ARIN…) | Which database answered |
| `resource` | `Domain Name` | `NetRange` / `CIDR` / `inetnum` / `route` | The object the response describes |
| `owner` | `Registrar` | org / `mnt-by` maintainer | Who controls the resource |
| `origin_as` | — | `OriginAS` / `origin:` | BGP-filter input the [CCC RIPE talk](#inspiration) focuses on |
| `registered` | `Creation Date` | `RegDate` / `created:` | Age — new registrations are suspicious |
| `updated` | `Updated Date` | `last-modified` | Recent repoint/takeover signal |
| `registry_expiry` | `Registry Expiry Date` | — | Short (1-year) registrations are a hunting signal |
| `name_server` | `Name Server` (set) | — | DNS hosting + pivot to related domains via shared NS |
| `status` | EPP codes | — | `serverHold`/`clientHold` = seized/sinkholed |
| `abuse_contact` | `Registrar Abuse Contact Email` | — | Abuse reporting + bulletproof-registrar fingerprinting |
| `reply_time` | request→reply delta | request→reply delta | Latency — tunneling/abuse signal |
| `reply_size` | total bytes | total bytes | Volume, without storing the blob |



## Protocol Reference

- [RFC 3912 - WHOIS Protocol Specification](https://datatracker.ietf.org/doc/html/rfc3912)
- [Wireshark WHOIS dissector](https://gitlab.com/wireshark/wireshark/-/blob/master/epan/dissectors/packet-whois.c)

## License

BSD-3-Clause, see [`COPYING`](COPYING).

## Credits

### Created

* Craig P ([@detection-labs](https://github.com/detection-labs))

### Thanks

* [Corelight](https://github.com/corelight)
* [Wireshark](https://gitlab.com/wireshark/wireshark)
* [tcpdump](https://github.com/the-tcpdump-group)

### Inspiration

* [*38th Chaos Communication Congress, 38c3: "The WHOIS protocol for internet routing policy, or: how plaintext retrieved over TCP/43 ends up in router configurations"*](https://media.ccc.de/v/38c3-the-whois-protocol-for-internet-routing-policy-or-how-plaintext-retrieved-over-tcp-43-ends-up-in-router-configurations) 
