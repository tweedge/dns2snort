from src.utilities import get_domain_segments, build_message, build_reference


def suricata5_dns_query(domain, sid, custom_message, reference):
    segments = get_domain_segments(domain)
    detect_domain = "." + ".".join(segments)  # dot prefixed

    # inject any custom metadata
    message = build_message(custom_message, "DNS Query", domain)
    ref = build_reference(reference)

    # construct the rule
    analyze = "alert dns $HOME_NET any -> any any"
    detect = f'dns.query; dotprefix; content:"{detect_domain}"; nocase; endswith;'
    metadata = f"{ref}sid:{sid}; rev:1;"

    rule_string = f"{analyze} ({message} {detect} {metadata})"
    return rule_string


def suricata5_http_host(domain, sid, custom_message, reference):
    segments = get_domain_segments(domain)
    detect_domain = "." + ".".join(segments)  # dot prefixed

    # inject any custom metadata
    message = build_message(custom_message, "HTTP Host", domain)
    ref = build_reference(reference)

    # construct the rule
    analyze = "alert http $HOME_NET any -> $EXTERNAL_NET any"
    filter = "flow:established,to_server; http.host;"
    detect = f'content:"{detect_domain}"; endswith;'
    metadata = f"{ref}sid:{sid}; rev:1;"

    rule_string = f"{analyze} ({message} {filter} {detect} {metadata})"
    return rule_string


def suricata5_tls_sni(domain, sid, custom_message, reference):
    segments = get_domain_segments(domain)
    detect_domain = ".".join(segments)

    # inject any custom metadata
    message = build_message(custom_message, "TLS SNI", domain)
    ref = build_reference(reference)

    # construct the rule
    analyze = "alert tls $HOME_NET any -> $EXTERNAL_NET any"
    filter = "flow:established,to_server; tls.sni;"
    detect = f'content:"{detect_domain}"; bsize:{len(detect_domain)}; fast_pattern;'
    metadata = f"{ref}sid:{sid}; rev:1;"

    rule_string = f"{analyze} ({message} {filter} {detect} {metadata})"
    return rule_string
