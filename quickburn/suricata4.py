from quickburn.utilities import get_domain_segments


def suricata4_dns(domain, sid, custom_message, reference):
    segments = get_domain_segments(domain)
    detect_domain = ".".join(segments)

    subdomains_regex = "/(?:^|\.)"
    subdomains_regex += detect_domain.replace("-", "\\-").replace(".", "\\.")
    subdomains_regex += "$/"

    # inject any custom metadata
    message = f'msg:"quickburn banned DNS domain {domain}";'
    if custom_message:
        arg_message = custom_message
        if "{domain}" in arg_message:
            imploded_domain = " .".join(segments)
            arg_message = arg_message.replace("{domain}", imploded_domain)
        message = f'msg:"{arg_message}";'

    ref = ""
    if reference:
        arg_ref = reference.replace("https://", "")
        ref = f"reference:url,{arg_ref}; "

    # construct the rule
    filter = "alert dns $HOME_NET any -> any any"
    detect = f'dns_query; content:"{detect_domain}"; nocase; isdataat:!1,relative;'
    detect_subdomains = f'pcre:"{subdomains_regex}";'
    metadata = f"sid:{sid}; {ref}rev:1;"

    rule_string = f"{filter} ({message} {detect} {detect_subdomains} {metadata})\n"
    return rule_string
