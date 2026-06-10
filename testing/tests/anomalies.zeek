# @TEST-EXEC: zeek -r ${TRACES}/whois-anomalies.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut uid service > conn.log.tmp && mv conn.log.tmp conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff whois.log
# @TEST-EXEC: btest-diff weird.log
#
# @TEST-DOC: Protocol anomalies that real servers cannot produce (synthetic, RFC 5737 TEST-NET endpoints): empty request, oversized query. Asserts the corresponding weirds fire.
