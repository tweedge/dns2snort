from src.snort import snort_http_host
from src.suricata4 import suricata4_http_host
from src.suricata5 import suricata5_http_host


domain = "now-dns.top"
sid = 2042939
message = "Dynamic DNS request"
reference = "https://raw.githubusercontent.com/MISP/misp-warninglists/main/lists/dynamic-dns/list.json"


def test_snort_http_host():
    generated_rule = snort_http_host(domain, sid, message, reference)
    assert (
        generated_rule
        == 'alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"Observed Dynamic DNS request (now-dns .top) in HTTP Host"; flow:established,to_server; content:".now-dns.top|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\\x3a\\x20[^\\r\\n]+\\.now-dns\\.top[\\r\\n]+$/Hmi"; reference:url,raw.githubusercontent.com/MISP/misp-warninglists/main/lists/dynamic-dns/list.json; sid:2042939; rev:1;)'
    )


def test_suricata4_http_host():
    generated_rule = suricata4_http_host(domain, sid, message, reference)
    assert (
        generated_rule
        == 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Observed Dynamic DNS request (now-dns .top) in HTTP Host"; flow:established,to_server; content:".now-dns.top"; http_host; isdataat:!1,relative; reference:url,raw.githubusercontent.com/MISP/misp-warninglists/main/lists/dynamic-dns/list.json; sid:2042939; rev:1;)'
    )


def test_suricata5_http_host():
    generated_rule = suricata5_http_host(domain, sid, message, reference)
    assert (
        generated_rule
        == 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Observed Dynamic DNS request (now-dns .top) in HTTP Host"; flow:established,to_server; http.host; content:".now-dns.top"; endswith; reference:url,raw.githubusercontent.com/MISP/misp-warninglists/main/lists/dynamic-dns/list.json; sid:2042939; rev:1;)'
    )
