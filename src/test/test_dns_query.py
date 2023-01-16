from src.snort import snort_dns_query
from src.suricata4 import suricata4_dns_query
from src.suricata5 import suricata5_dns_query


domain = "privatproxy-blog.xyz"
sid = 2043105
message = "ViperSoftX CnC"
reference = "https://chris.partridge.tech/2022/evolution-of-vipersoftx-dga/"


def test_snort_dns_query():
    generated_rule = snort_dns_query(domain, sid, message, reference)
    assert (
        generated_rule
        == 'alert udp $HOME_NET any -> any 53 (msg:"Observed ViperSoftX CnC (privatproxy-blog .xyz) in DNS Query"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|10|privatproxy-blog|03|xyz|00|"; nocase; distance:0; fast_pattern; reference:url,chris.partridge.tech/2022/evolution-of-vipersoftx-dga/; sid:2043105; rev:1;)'
    )


def test_suricata4_dns_query():
    generated_rule = suricata4_dns_query(domain, sid, message, reference)
    assert (
        generated_rule
        == 'alert dns $HOME_NET any -> any any (msg:"Observed ViperSoftX CnC (privatproxy-blog .xyz) in DNS Query"; dns_query; content:"privatproxy-blog.xyz"; nocase; isdataat:!1,relative; pcre:"/(?:^|\\.)privatproxy\\-blog\\.xyz$/"; reference:url,chris.partridge.tech/2022/evolution-of-vipersoftx-dga/; sid:2043105; rev:1;)'
    )


def test_suricata5_dns_query():
    generated_rule = suricata5_dns_query(domain, sid, message, reference)
    assert (
        generated_rule
        == 'alert dns $HOME_NET any -> any any (msg:"Observed ViperSoftX CnC (privatproxy-blog .xyz) in DNS Query"; dns.query; dotprefix; content:".privatproxy-blog.xyz"; nocase; endswith; reference:url,chris.partridge.tech/2022/evolution-of-vipersoftx-dga/; sid:2043105; rev:1;)'
    )
