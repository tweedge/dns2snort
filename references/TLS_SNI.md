# TLS SNI Rule Examples

These are reference rules used in `quickburn` development + validation from https://rules.emergingthreats.net/open/

## Snort (Edge and non-Edge)

```
alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg:"ET TROJAN Observed linux.backdoor.wordpressexploit.2 Domain (letsmakeparty3 .ga) in TLS SNI"; flow:established,to_server; content:"|16|"; content:"|01|"; within:8; content:"|00 00 11|letsmakeparty3.ga"; distance:0; fast_pattern; reference:md5,4d83619142c7f7e3bd1531f8111e2655; reference:url,vms.drweb.com/virus/?i=25604745; classtype:trojan-activity; sid:2043189; rev:1; metadata:affected_product Wordpress, attack_target Client_Endpoint, created_at 2023_01_03, deployment Perimeter, performance_impact Low, signature_severity Major, updated_at 2023_01_03;)
```

## Suricata 4

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET TROJAN Observed linux.backdoor.wordpressexploit.2 Domain (letsmakeparty3 .ga) in TLS SNI"; flow:established,to_server; tls_sni; content:"letsmakeparty3.ga"; depth:17; isdataat:!1,relative; reference:md5,4d83619142c7f7e3bd1531f8111e2655; reference:url,vms.drweb.com/virus/?i=25604745; classtype:trojan-activity; sid:2043189; rev:1; metadata:affected_product Wordpress, attack_target Client_Endpoint, created_at 2023_01_03, deployment Perimeter, performance_impact Low, signature_severity Major, updated_at 2023_01_03;)
```

# Suricata 5

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"ET MALWARE Observed linux.backdoor.wordpressexploit.2 Domain (letsmakeparty3 .ga) in TLS SNI"; flow:established,to_server; tls.sni; content:"letsmakeparty3.ga"; bsize:17; fast_pattern; reference:md5,4d83619142c7f7e3bd1531f8111e2655; reference:url,vms.drweb.com/virus/?i=25604745; classtype:command-and-control; sid:2043189; rev:1; metadata:affected_product Wordpress, attack_target Client_Endpoint, created_at 2023_01_03, deployment Perimeter, performance_impact Low, signature_severity Major, updated_at 2023_01_03;)
```
