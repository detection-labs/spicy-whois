##! Implements base functionality for WHOIS analysis.
##! Generates whois.log with structured field extraction, the logging model is
##! to log request and (selected) reply artefacts in a single record.
##!
##! Parsing and field extraction happen in the Spicy analyzer; this script
##! copies the extracted fields into the log record and computes the request-to-
##! reply timing (which spans two events and so must live in Zeek).
##!
##! See :rfc:`3912`.

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
	## request: The parsed request unit, carrying ``query`` (stripped of the
	##          line terminator) and ``query_type`` (domain, ipv4, ipv6, or asn).
	##
	## .. zeek:see:: WHOIS::reply
	global WHOIS::request: event(c: connection, is_orig: bool, request: WHOIS::Request);

	## Generated for WHOIS replies, carrying the fields the analyzer extracted
	## from the reply text.
	##
	## c: The connection.
	##
	## is_orig: True if from the originator.
	##
	## reply: The parsed reply unit, carrying the extracted fields (resource,
	##        owner, origin_as, dates, name_server/status sets, reply_size, ...).
	##
	## .. zeek:see:: WHOIS::request
	global WHOIS::reply: event(c: connection, is_orig: bool, reply: WHOIS::Reply);

	## WHOIS finalization hook.
	global finalize_whois: Conn::RemovalHook;
}

redef record connection += {
	whois: Info &optional;
};

redef likely_server_ports += { ports };

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

event WHOIS::request(c: connection, is_orig: bool, request: WHOIS::Request)
	{
	hook set_session(c);

	c$whois$query = request$query;
	c$whois$query_type = request$query_type;
	c$whois$request_time = network_time();
	}

event WHOIS::reply(c: connection, is_orig: bool, reply: WHOIS::Reply)
	{
	hook set_session(c);

	local w = c$whois;
	w$reply_size = reply$reply_size;

	if ( w?$request_time )
		w$reply_time = network_time() - w$request_time;

	if ( |reply$resource| > 0 )
		w$resource = reply$resource;
	if ( |reply$owner| > 0 )
		w$owner = reply$owner;
	if ( |reply$origin_as| > 0 )
		w$origin_as = reply$origin_as;
	if ( |reply$registered| > 0 )
		w$registered = reply$registered;
	if ( |reply$updated| > 0 )
		w$updated = reply$updated;
	if ( |reply$registry_expiry| > 0 )
		w$registry_expiry = reply$registry_expiry;
	if ( |reply$abuse_contact| > 0 )
		w$abuse_contact = reply$abuse_contact;
	if ( |reply$server_name| > 0 )
		w$server_name = reply$server_name;
	if ( |reply$name_server| > 0 )
		w$name_server = reply$name_server;
	if ( |reply$status| > 0 )
		w$status = reply$status;
	}

hook finalize_whois(c: connection)
	{
	if ( c?$whois && ! c$whois$violation )
		Log::write(WHOIS::LOG, c$whois);
	}
