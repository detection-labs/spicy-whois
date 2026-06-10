# @TEST-EXEC: zeek -r ${TRACES}/whois-idn.pcap ${PACKAGE} %INPUT
# @TEST-EXEC: cat conn.log | zeek-cut uid service > conn.log.tmp && mv conn.log.tmp conn.log
# @TEST-EXEC: btest-diff conn.log
# @TEST-EXEC: btest-diff whois.log
#
# @TEST-DOC: UTF-8/IDN handling from genuine CJK lookups (日本語.jp, 中国.cn, 한국.kr) plus mixed-script homograph queries sent as ACE/punycode (xn--80ak6aa92e.com, xn--pypal-4ve.com, xn--pic-pma.com, xn--bcher-kva.de).
