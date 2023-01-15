#!/usr/bin/python3
import argparse
from quickburn.snort import snort_dns_query, snort_tls_sni
from quickburn.suricata4 import suricata4_dns_query, suricata4_tls_sni
from quickburn.suricata5 import suricata5_dns_query, suricata5_tls_sni

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
    help="The name of the file to output your Snort rules to.",
)
parser.add_argument(
    "--sid",
    type=int,
    required=True,
    help="The Snort SID to start numbering incrementally at. This number should be between 1000000 and 2000000.",
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
args = parser.parse_args()

# This is a small check to ensure -s is set to a valid value between one and two million - the local rules range.
why_failed = ""
if args.sid < 1000000:
    why_failed = "low"
elif args.sid > 2000000:
    why_failed = "high"

if why_failed:
    print(f"SID is too {why_failed}. Valid SID range is 1000000 to 2000000 (1m to 2m)")
    exit()

rules_out_file = open(args.output, "w")
domains_in_file = open(args.input, "r")
sid = args.sid

for line in domains_in_file:
    domain = line.rstrip()

    # skip empty lines
    if domain == "":
        continue

    rule_string = snort_tls_sni(domain, sid, args.reason, args.reference)

    rules_out_file.write(rule_string)

    sid += 1
