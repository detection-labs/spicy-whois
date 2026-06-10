# @TEST-EXEC: zeek -r ${TRACES}/whois-domain.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut uid service > conn.log.tmp && mv conn.log.tmp conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff whois.log
#
# @TEST-DOC: Domain-world extraction from genuine registrar lookups (cloudflare.com, amazon.com): registrar owner, EPP status set, abuse_contact, creation/updated/expiry dates, name_server set.
