# @TEST-EXEC: zeek -r ${TRACES}/whois-no-reply.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut uid service > conn.log.tmp && mv conn.log.tmp conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff whois.log
#
# @TEST-DOC: Request-only path: client sends a query, server never responds at all (no ACK of the query, no reply, never closes; half-open). WHOIS::request fires off the parsed query alone, finalize_whois logs the record at trace EOF with query/query_type set but reply_size, reply_time, and all parsed reply fields unset.
