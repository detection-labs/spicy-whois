# @TEST-DOC: Check that the WHOIS analyzer is available.
#
# @TEST-EXEC: zeek -NN | grep -qi 'ANALYZER_SPICY__\?WHOIS\|ANALYZER_WHOIS'
