from quickburn.utilities import get_domain_segments, build_message


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
    default_message = "quickburn banned DNS domain"
    message = build_message(default_message, custom_message, domain)

    ref = ""
    if reference:
        arg_ref = reference.replace("https://", "")
        ref = f"reference:url,{arg_ref}; "

    # construct the rule
    filter = "alert udp $HOME_NET any -> any 53"
    dns_queries_only = 'content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7;'
    detect = f"content:{content}; nocase; distance:0; fast_pattern;"
    metadata = f"sid:{sid}; {ref}rev:1;"

    rule_string = f"{filter} ({message} {dns_queries_only} {detect} {metadata})\n"
    return rule_string
