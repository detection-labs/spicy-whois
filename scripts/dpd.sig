signature dpd_whois_client {
  ip-proto == tcp
  tcp-state originator
  # Character class: domain/IP/ASN chars, plus flag punctuation (- . @ = / + : ,)
  #   and a literal space for flag-style queries (e.g. "-T dn,ace example.de").
  # \x80-\xff : UTF-8 high bytes for IDN/CJK queries.
  # No \s : a single query line must not contain internal CR/LF/tab, so multi-line
  #   payloads (e.g. "foo.com\r\nbar.com\r\n") are rejected as non-WHOIS.
  # {1,128}   : reasonable length bound for a query.
  # \x0d\x0a$ : the line ends with exactly one trailing CRLF.
  payload /^[a-zA-Z0-9\x80-\xff.@=\/+:, -]{1,128}\x0d\x0a$/
}

signature dpd_whois_server {
  ip-proto == tcp
  tcp-state responder
  requires-reverse-signature dpd_whois_client
  # WHOIS responses have no standard format, but almost always contain certain words.
  # (?i:...) makes the match case-insensitive.
  # Keywords from RIRs, registrars, ccTLDs (including CJK servers).
  # route6? + origin:/source: cover RPSL routing objects, incl. IPv6 route6: blocks.
  # Leading .* : Zeek anchors payload patterns at offset 0, so without it a keyword
  #   that isn't the first bytes of the reply (e.g. "   Domain Name") never matches.
  payload /.*(?i:whois|domain name|registrar|inetnum|route6?:|netrange|netname|orgname|% iana|% this is|nserver|name server|created:|registration date|domain status|origin:|source:)/
  enable "WHOIS"
}
