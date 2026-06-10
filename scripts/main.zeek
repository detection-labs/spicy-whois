##! Implements base functionality for WHOIS analysis.
##! Generates whois.log with structured field extraction, the logging model is
##! to log request and (selected) reply artefacts in a single record.
##!
##! See :rfc:`3912`.

@load base/frameworks/notice/weird
@load base/protocols/conn/removal-hooks

module WHOIS;

export {
	## The protocol logging stream identifier.
	redef enum Log::ID += { LOG };

	## A default logging policy hook for the stream.
	global log_policy: Log::PolicyHook;

	## Well-known port for WHOIS.
	const ports = {
		43/tcp,
	} &redef;

	## The record type which contains the fields of the WHOIS log.
	type Info: record {
		## Timestamp for when the activity happened.
		ts: time &log;
		## Unique ID for the connection.
		uid: string &log;
		## The connection's 4-tuple of endpoint addresses/ports.
		id: conn_id &log;
		## The WHOIS query sent by the client.
		query: string &log &optional;
		## Classification of the query: domain, ipv4, ipv6, or asn.
		query_type: string &log &optional;
		## Source registry from the reply's `source:` line (RIR responses only).
		server_name: string &log &optional;
		## The object the response describes (domain, net range, or route).
		resource: string &log &optional;
		## Who controls the resource (registrar, org, or RIR maintainer).
		owner: string &log &optional;
		## Origin AS for a routing object (the BGP-filter input).
		origin_as: string &log &optional;
		## Registration/creation date.
		registered: string &log &optional;
		## Last-updated date.
		updated: string &log &optional;
		## Registry expiry/paid-till date (domain responses).
		registry_expiry: string &log &optional;
		## Authoritative name servers (domain responses).
		name_server: set[string] &log &optional;
		## Status values (EPP codes for domains).
		status: set[string] &log &optional;
		## Registrar abuse contact email.
		abuse_contact: string &log &optional;
		## Time between request and reply.
		reply_time: interval &log &optional;
		## Total reply size in bytes.
		reply_size: count &log &optional;
		## Timestamp of request (internal, not logged).
		request_time: time &optional;
		## Set when the analyzer reports a violation; suppresses logging
		## of partial/garbage data (internal, not logged).
		violation: bool &default=F;
	};

	## Event that can be handled to access the WHOIS logging record.
	global log_whois: event(rec: Info);

	## Generated for WHOIS requests.
	##
	## c: The connection.
	##
	## is_orig: True if from the originator.
	##
	## query: The WHOIS query string, stripped of the line terminator.
	##
	## .. zeek:see:: WHOIS::reply
	global WHOIS::request: event(c: connection, is_orig: bool, query: string);

	## Generated for WHOIS replies.
	##
	## c: The connection.
	##
	## is_orig: True if from the originator.
	##
	## data: The full server reply text, read until connection close.
	##
	## .. zeek:see:: WHOIS::request
	global WHOIS::reply: event(c: connection, is_orig: bool, data: string);

	## WHOIS finalization hook.
	global finalize_whois: Conn::RemovalHook;
}

redef record connection += {
	whois: Info &optional;
};

redef likely_server_ports += { ports };

function classify_query(query: string): string
	{
	if ( /^[Aa][Ss][0-9]+$/ == query )
		return "asn";

	if ( is_valid_ip(query) )
		return /:/ in query ? "ipv6" : "ipv4";

	return "domain";
	}

function parse_reply(c: connection, data: string)
	{
	local w = c$whois;
	local st: set[string];
	local ns: set[string];

	for ( _, line in split_string(data, /\x0a/) )
		{
		local kv = split_string1(line, /:[[:blank:]]*/);
		if ( |kv| != 2 )
			next;

		local key = to_lower(strip(kv[0]));
		local val = strip(kv[1]);

		if ( |val| == 0 )
			next;

		if ( ! w?$resource && /^(domain name|netrange|cidr|inetnum|route|route6)$/ == key )
			w$resource = val;

		else if ( ! w?$owner && /^(registrar|org|org-name|orgname|organi[sz]ation|mnt-by)$/ == key )
			w$owner = val;

		else if ( ! w?$origin_as && /^(originas|origin)$/ == key )
			w$origin_as = val;

		else if ( ! w?$registered && /^(creation date|created|regdate)$/ == key )
			w$registered = val;

		else if ( ! w?$updated && /^(updated date|updated|last-modified)$/ == key )
			w$updated = val;

		# Anchoring is load-bearing: keys are matched whole (/^...$/) so
		# boilerplate prose ("NOTICE: the expiration date ...") splits to
		# key "notice" and cannot false-match these date labels.
		else if ( ! w?$registry_expiry && /^(registry expiry date|registrar registration expiration date|expiry date|expiration date|paid-till)$/ == key )
			w$registry_expiry = val;

		else if ( ! w?$abuse_contact && /abuse contact email/ in key )
			w$abuse_contact = val;

		else if ( /^(domain status|status)$/ == key )
			add st[val];

		else if ( /^(name server|nserver)$/ == key )
			add ns[to_lower(val)];

		else if ( ! w?$server_name && /^source$/ == key )
			w$server_name = val;
		}

	if ( |st| > 0 )
		w$status = st;

	if ( |ns| > 0 )
		w$name_server = ns;
	}

event zeek_init() &priority=5
	{
	Log::create_stream(WHOIS::LOG, Log::Stream($columns=Info, $ev=log_whois, $path="whois", $policy=log_policy));
	Analyzer::register_for_ports(Analyzer::ANALYZER_WHOIS, ports);
	}

hook set_session(c: connection)
	{
	if ( c?$whois )
		return;

	c$whois = Info($ts=network_time(), $uid=c$uid, $id=c$id);
	Conn::register_removal_hook(c, finalize_whois);
	}

event analyzer_violation_info(atype: AllAnalyzers::Tag,
    info: AnalyzerViolationInfo)
	{
	if ( atype == Analyzer::ANALYZER_WHOIS && info?$c && info$c?$whois )
		info$c$whois$violation = T;
	}

event WHOIS::request(c: connection, is_orig: bool, query: string)
	{
	hook set_session(c);

	c$whois$query = query;
	c$whois$query_type = classify_query(query);
	c$whois$request_time = network_time();

	if ( |query| == 0 )
		Reporter::conn_weird("whois_empty_request", c, "client sent empty WHOIS request");

	if ( |query| > 512 )
		Reporter::conn_weird("whois_oversized_request", c,
		    fmt("query length %d is unusually large for a WHOIS request", |query|));
	}

event WHOIS::reply(c: connection, is_orig: bool, data: string)
	{
	hook set_session(c);

	c$whois$reply_size = |data|;

	if ( c$whois?$request_time )
		c$whois$reply_time = network_time() - c$whois$request_time;

	parse_reply(c, data);
	}

hook finalize_whois(c: connection)
	{
	if ( c?$whois && ! c$whois$violation )
		Log::write(WHOIS::LOG, c$whois);
	}
