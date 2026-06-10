# PCAP test traces

Function/test aligned pcaps. Three contain **bona-fide** WHOIS traffic captured
against live public servers (client `192.168.1.231`); two are **synthetic** for
behaviours a compliant server cannot produce (protocol anomalies; a request that
never gets a reply).

| Fixture | Provenance | What it exercises |
|---------|------------|-------------------|
| `whois-domain.pcap` | real (verisign-grs) | Domain world: registrar `owner`, EPP `status` set, `abuse_contact`, creation/updated dates (cloudflare.com, amazon.com) |
| `whois-net.pcap` | real (RIPE, APNIC) | Network world: `resource` net range, `mnt-by` owner, `origin_as`, `source` server_name, `ipv4`/`asn` query_type |
| `whois-idn.pcap` | real (JPRS, CNNIC, KISA, DENIC, verisign) | UTF-8 CJK queries (日本語.jp, 中国.cn, 한국.kr) + mixed-script homographs sent as ACE/punycode (xn--…) |
| `whois-anomalies.pcap` | **synthetic** (RFC 5737 TEST-NET endpoints) | bare-LF request, empty request, oversized query → weirds |
| `whois-no-reply.pcap` | **synthetic** (RFC 5737 TEST-NET endpoints) | request-only / half-open connection → record with reply fields unset |

Pcaps were anonymised at Layer 2 by re-encapsulating Eth as **Linux cooked (SLL)**: contains
no hardware MACs (SLL has no dst MAC; the src lladdr is zeroed), direction is
carried in SLL's `pkttype` field (4 = client→server, 0 = server→client). 

IP Addressing: RFC 1918 client (`192.168.x`) and public registry server IPs in first 3; synthetic
endpoints are `198.51.100.10` → `203.0.113.43` (RFC 5737 TEST-NET) so
crafted packets are obvious.
