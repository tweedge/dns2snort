def get_domain_segments(domain):
    segments = domain.split(".")

    # remove blank strings in index 0 (ex. where ".tld" is split into ["", "tld"])
    if segments[0] == "":
        segments = segments[1:]

    return segments

def build_message(default_message, custom_message, domain):
    message = default_message

    if custom_message:
        message = custom_message

    et_format_domain = " .".join(get_domain_segments(domain))

    return f'msg:"{message} ({et_format_domain})";'