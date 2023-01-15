# DNS Query Rule Examples

These are reference rules used in `quickburn` development + validation from https://rules.emergingthreats.net/open/

## Snort (Edge and non-Edge)

```
alert udp $HOME_NET any -> any 53 (msg:"ET TROJAN ViperSoftX CnC Domain in DNS Lookup (privatproxy-blog .xyz)"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|10|privatproxy-blog|03|xyz|00|"; nocase; distance:0; fast_pattern; reference:url,chris.partridge.tech/2022/evolution-of-vipersoftx-dga/; classtype:trojan-activity; sid:2043105; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2022_12_30, deployment Perimeter, malware_family ViperSoftX, performance_impact Low, signature_severity Major, updated_at 2022_12_30;)
```

## Suricata 4

```
alert dns $HOME_NET any -> any any (msg:"ET TROJAN ViperSoftX CnC Domain in DNS Lookup (privatproxy-blog .xyz)"; dns_query; content:"privatproxy-blog.xyz"; nocase; isdataat:!1,relative; pcre:"/(?:^|\.)privatproxy\-blog\.xyz$/"; reference:url,chris.partridge.tech/2022/evolution-of-vipersoftx-dga/; classtype:trojan-activity; sid:2043105; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2022_12_30, deployment Perimeter, malware_family ViperSoftX, performance_impact Low, signature_severity Major, updated_at 2022_12_30;)
```

# Suricata 5

```
alert dns $HOME_NET any -> any any (msg:"ET MALWARE ViperSoftX CnC Domain in DNS Lookup (privatproxy-blog .xyz)"; dns.query; dotprefix; content:".privatproxy-blog.xyz"; nocase; endswith; reference:url,chris.partridge.tech/2022/evolution-of-vipersoftx-dga/; classtype:domain-c2; sid:2043105; rev:1; metadata:affected_product Windows_XP_Vista_7_8_10_Server_32_64_Bit, attack_target Client_Endpoint, created_at 2022_12_30, deployment Perimeter, malware_family ViperSoftX, performance_impact Low, signature_severity Major, updated_at 2022_12_30;)
```