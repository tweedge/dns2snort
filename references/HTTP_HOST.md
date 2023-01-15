# HTTP Host Rule Examples

These are reference rules used in `quickburn` development + validation from https://rules.emergingthreats.net/open/

## Snort (Edge and non-Edge)

```
alert tcp $HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.now-dns .top Domain"; flow:established,to_server; content:".now-dns.top|0d 0a|"; http_header; fast_pattern; pcre:"/^Host\x3a\x20[^\r\n]+\.now-dns\.top[\r\n]+$/Hmi"; reference:url,raw.githubusercontent.com/MISP/misp-warninglists/main/lists/dynamic-dns/list.json; classtype:bad-unknown; sid:2042939; rev:1; metadata:attack_target Client_and_Server, created_at 2022_12_15, deployment Perimeter, signature_severity Informational, updated_at 2022_12_15;)
```

## Suricata 4

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.now-dns .top Domain"; flow:established,to_server; content:".now-dns.top"; http_host; isdataat:!1,relative; reference:url,raw.githubusercontent.com/MISP/misp-warninglists/main/lists/dynamic-dns/list.json; classtype:bad-unknown; sid:2042939; rev:1; metadata:attack_target Client_and_Server, created_at 2022_12_15, deployment Perimeter, signature_severity Informational, updated_at 2022_12_15;)
```

# Suricata 5

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"ET INFO DYNAMIC_DNS HTTP Request to a *.now-dns .top Domain"; flow:established,to_server; http.host; content:".now-dns.top"; endswith; reference:url,raw.githubusercontent.com/MISP/misp-warninglists/main/lists/dynamic-dns/list.json; classtype:bad-unknown; sid:2042939; rev:1; metadata:attack_target Client_and_Server, created_at 2022_12_15, deployment Perimeter, signature_severity Informational, updated_at 2022_12_15;)
```