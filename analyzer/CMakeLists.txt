spicy_add_analyzer(
    NAME WHOIS
    PACKAGE_NAME spicy-whois
    SOURCES whois.spicy whois.evt zeek_whois.spicy
    SCRIPTS __load__.zeek main.zeek dpd.sig)
