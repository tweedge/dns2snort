import argparse, os
from src.snort import snort_dns_query, snort_http_host, snort_tls_sni
from src.suricata4 import suricata4_dns_query, suricata4_http_host, suricata4_tls_sni
from src.suricata5 import suricata5_dns_query, suricata5_http_host, suricata5_tls_sni

description = """Given a file containing a list of FQDNs, quickly generate Snort rules for those domains.\n
Brought to you by @da_667, @botnet_hunter, @3XPlo1T2, and tweedge."""

parser = argparse.ArgumentParser(description=description)

parser.add_argument(
    "--input",
    required=True,
    help="The name of the file containing a list of domains, one domain per line.",
)
parser.add_argument(
    "--output",
    required=True,
    help="The name of the folder to output your IPS rules to.",
)
parser.add_argument(
    "--sid",
    type=int,
    default=1000000,
    help="Optional: The SID to start numbering incrementally at (must be between 1000000 and 2000000)",
)
parser.add_argument(
    "--reason",
    type=str,
    help="Optional: A custom reason to include in the rule's message (ex. 'ViperSoftX CnC')",
)
parser.add_argument(
    "--reference",
    type=str,
    help="Optional: A reference URL to include in the rule",
)
parser.add_argument(
    "--dns",
    action="store_true",
    help="Generate IPS rules to find domains in DNS queries",
)
parser.add_argument(
    "--http",
    action="store_true",
    help="Generate IPS rules to find domains in HTTP host headers",
)
parser.add_argument(
    "--tls",
    action="store_true",
    help="Generate IPS rules to find domains in TLS SNI fields",
)
args = parser.parse_args()

if not (args.dns or args.http or args.tls):
    print("You must select at least one type of rule to generate (check --help!)")
    exit(1)

# This is a small check to ensure -s is set to a valid value between one and two million - the local rules range.
why_failed = ""
if args.sid < 1000000:
    why_failed = "low"
elif args.sid > 2000000:
    why_failed = "high"

if why_failed:
    print(f"SID is too {why_failed}. Valid SID range is 1000000 to 2000000 (1m to 2m)")
    exit(1)

domains_in_file = open(args.input, "r")
domains = []
for line in domains_in_file:
    domain = line.rstrip()

    # skip empty lines
    if domain == "":
        continue

    domains.append(domain)

os.makedirs(args.output, exist_ok=True)

generator_map = {
    "snort.rules": {
        "dns": snort_dns_query,
        "http": snort_http_host,
        "tls": snort_tls_sni,
    },
    "suricata4.rules": {
        "dns": suricata4_dns_query,
        "http": suricata4_http_host,
        "tls": suricata4_tls_sni,
    },
    "suricata5.rules": {
        "dns": suricata5_dns_query,
        "http": suricata5_http_host,
        "tls": suricata4_tls_sni,
    },
}

for rule_file, generator_functions in generator_map.items():
    sid = args.sid
    rules_out_file = open(os.path.join(args.output, rule_file), "w")

    if args.dns:
        generator = generator_functions["dns"]
        for domain in domains:
            rule_string = generator(domain, sid, args.reason, args.reference)
            rules_out_file.write(f"{rule_string}\n")
            sid += 1

    if args.http:
        generator = generator_functions["http"]
        for domain in domains:
            rule_string = generator(domain, sid, args.reason, args.reference)
            rules_out_file.write(f"{rule_string}\n")
            sid += 1

    if args.tls:
        generator = generator_functions["tls"]
        for domain in domains:
            rule_string = generator(domain, sid, args.reason, args.reference)
            rules_out_file.write(f"{rule_string}\n")
            sid += 1
