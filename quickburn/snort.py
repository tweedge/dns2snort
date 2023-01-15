from quickburn.utilities import get_domain_segments, build_message, build_reference


def snort_dns(domain, sid, custom_message, reference):
    segments = get_domain_segments(domain)
    content = ""

    for segment in segments:
        segment_len_hex = hex(len(segment))[2:]
        if len(segment_len_hex) == 1:
            segment_len_hex = "0%s" % segment_len_hex
        content += f"|{segment_len_hex}|{segment}"
    content = f'"{content}|00|"'

    # inject any custom metadata
    message = build_message(custom_message, "DNS Query", domain)
    ref = build_reference(reference)

    # construct the rule
    analyze = "alert udp $HOME_NET any -> any 53"
    filter = 'content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7;'
    detect = f"content:{content}; nocase; distance:0; fast_pattern;"
    metadata = f"sid:{sid}; {ref}rev:1;"

    rule_string = f"{analyze} ({message} {filter} {detect} {metadata})\n"
    return rule_string

def snort_tls_sni(domain, sid, custom_message, reference):
    segments = get_domain_segments(domain)
    detect_domain = ".".join(segments)

    domain_length = len(detect_domain)
    length_as_hex = str(hex(domain_length))[2:]
    if len(length_as_hex) < 2:
        length_as_hex = "0" + length_as_hex

    # inject any custom metadata
    message = build_message(custom_message, "TLS SNI", domain)
    ref = build_reference(reference)

    # construct the rule
    analyze = "alert tcp $HOME_NET any -> $EXTERNAL_NET 443"
    filter = 'flow:established,to_server; content:"|16|"; content:"|01|"; within:8;'
    detect = f'content:"|00 00 {length_as_hex}|{detect_domain}"; distance:0; fast_pattern;'
    metadata = f"sid:{sid}; {ref}rev:1;"

    rule_string = f"{analyze} ({message} {filter} {detect} {metadata})\n"
    return rule_string

