# @TEST-EXEC: zeek -r ${TRACES}/whois-net.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut uid service > conn.log.tmp && mv conn.log.tmp conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff whois.log
#
# @TEST-DOC: Network-world extraction from genuine RIR lookups (RIPE inetnum + origin_as, APNIC, RIPE ASN): resource net range, mnt-by owner, origin_as, source server_name, ipv4/asn query_type.
