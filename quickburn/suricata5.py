from quickburn.utilities import get_domain_segments, build_message


def suricata5_dns(domain, sid, custom_message, reference):
    segments = get_domain_segments(domain)
    detect_domain = "." + ".".join(segments)

    # inject any custom metadata
    default_message = "quickburn banned DNS domain"
    message = build_message(default_message, custom_message, domain)

    ref = ""
    if reference:
        arg_ref = reference.replace("https://", "")
        ref = f"reference:url,{arg_ref}; "

    # construct the rule
    filter = "alert dns $HOME_NET any -> any any"
    detect = f'dns.query; dotprefix; content:"{detect_domain}"; nocase; endswith;'
    metadata = f"sid:{sid}; {ref}rev:1;"

    rule_string = f"{filter} ({message} {detect} {metadata})\n"
    return rule_string
