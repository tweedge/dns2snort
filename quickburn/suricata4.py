from quickburn.utilities import get_domain_segments, build_message, build_reference


def suricata4_dns_query(domain, sid, custom_message, reference):
    segments = get_domain_segments(domain)
    detect_domain = ".".join(segments)

    subdomains_regex = "/(?:^|\.)"
    subdomains_regex += detect_domain.replace("-", "\\-").replace(".", "\\.")
    subdomains_regex += "$/"

    # inject custom metadata
    message = build_message(custom_message, "DNS Query", domain)
    ref = build_reference(reference)

    # construct the rule
    analyze = "alert dns $HOME_NET any -> any any"
    detect = f'dns_query; content:"{detect_domain}"; nocase; isdataat:!1,relative;'
    detect_subdomains = f'pcre:"{subdomains_regex}";'
    metadata = f"sid:{sid}; {ref}rev:1;"

    rule_string = f"{analyze} ({message} {detect} {detect_subdomains} {metadata})\n"
    return rule_string


def suricata4_http_host(domain, sid, custom_message, reference):
    segments = get_domain_segments(domain)
    detect_domain = "." + ".".join(segments)  # dot prefixed

    # inject any custom metadata
    message = build_message(custom_message, "HTTP Host", domain)
    ref = build_reference(reference)

    # construct the rule
    analyze = "alert http $HOME_NET any -> $EXTERNAL_NET any"
    filter = "flow:established,to_server;"
    detect = f'content:"{detect_domain}"; http_host; isdataat:!1,relative;'
    metadata = f"sid:{sid}; {ref}rev:1;"

    rule_string = f"{analyze} ({message} {filter} {detect} {metadata})\n"
    return rule_string


def suricata4_tls_sni(domain, sid, custom_message, reference):
    segments = get_domain_segments(domain)
    detect_domain = ".".join(segments)

    # inject any custom metadata
    message = build_message(custom_message, "TLS SNI", domain)
    ref = build_reference(reference)

    # construct the rule
    analyze = "alert tls $HOME_NET any -> $EXTERNAL_NET any"
    filter = "flow:established,to_server; tls_sni;"
    detect = (
        f'content:"{detect_domain}"; depth:{len(detect_domain)}; isdataat:!1,relative;'
    )
    metadata = f"sid:{sid}; {ref}rev:1;"

    rule_string = f"{analyze} ({message} {filter} {detect} {metadata})\n"
    return rule_string
