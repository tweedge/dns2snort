def get_domain_segments(domain):
    segments = domain.split(".")

    # remove blank strings in index 0 (ex. where ".tld" is split into ["", "tld"])
    if segments[0] == "":
        segments = segments[1:]

    return segments


def build_message(custom_message, found_where, domain):
    if custom_message:
        message = f"Observed {custom_message}"
    else:
        message = "Banned"

    et_format_domain = " .".join(get_domain_segments(domain))

    return f'msg:"{message} ({et_format_domain}) in {found_where}";'


def build_reference(reference):
    ref = ""
    if reference:
        reference_without_proto = reference.replace("https://", "")
        ref = f"reference:url,{reference_without_proto}; "
    return ref
