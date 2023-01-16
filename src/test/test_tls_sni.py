from ..snort import snort_tls_sni
from ..suricata4 import suricata4_tls_sni
from ..suricata5 import suricata5_tls_sni


domain = "letsmakeparty3.ga"
sid = 2043189
message = "linux.backdoor.wordpressexploit.2 Domain"
reference = "https://vms.drweb.com/virus/?i=25604745"


def test_snort_tls_sni():
    generated_rule = snort_tls_sni(domain, sid, message, reference)
    assert (
        generated_rule.strip()
        == 'alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"Observed linux.backdoor.wordpressexploit.2 Domain (letsmakeparty3 .ga) in TLS SNI"; flow:established,to_server; content:"|16|"; content:"|01|"; within:8; content:"|00 00 11|letsmakeparty3.ga"; distance:0; fast_pattern; reference:url,vms.drweb.com/virus/?i=25604745; sid:2043189; rev:1;)'
    )


def test_suricata4_tls_sni():
    generated_rule = suricata4_tls_sni(domain, sid, message, reference)
    assert (
        generated_rule.strip()
        == 'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Observed linux.backdoor.wordpressexploit.2 Domain (letsmakeparty3 .ga) in TLS SNI"; flow:established,to_server; tls_sni; content:"letsmakeparty3.ga"; depth:17; isdataat:!1,relative; reference:url,vms.drweb.com/virus/?i=25604745; sid:2043189; rev:1;)'
    )


def test_suricata5_tls_sni():
    generated_rule = suricata5_tls_sni(domain, sid, message, reference)
    assert (
        generated_rule.strip()
        == 'alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"Observed linux.backdoor.wordpressexploit.2 Domain (letsmakeparty3 .ga) in TLS SNI"; flow:established,to_server; tls.sni; content:"letsmakeparty3.ga"; bsize:17; fast_pattern; reference:url,vms.drweb.com/virus/?i=25604745; sid:2043189; rev:1;)'
    )
