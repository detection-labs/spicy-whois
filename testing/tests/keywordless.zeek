# @TEST-EXEC: zeek -r ${TRACES}/whois-keywordless.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut uid service > conn.log.tmp && mv conn.log.tmp conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff whois.log
#
# @TEST-DOC: A genuine WHOIS reply with no extractable key/value fields (here a registrar "# Not found" response) must still confirm: service=whois in conn.log and a whois.log row with the query logged, even though every extracted field is empty. Guards against re-introducing reply-structure gating, which would false-negative the many keywordless-but-real WHOIS replies (IRR route dumps, "# Not found", "Out of this registry.").
