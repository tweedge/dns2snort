#!/usr/bin/python3
import argparse
from quickburn.snort import snort_dns
from quickburn.suricata4 import suricata4_dns
from quickburn.suricata5 import suricata5_dns

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
    "--message",
    type=str,
    help="Optional: A custom message to include in the rule",
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

# rules_out_file is the file we will be outputting our rules to.
# domains_in_file is the file we will read a list of domains from.
# This script iterates through each line (via for line loop) and splits on periods (.), creating a list for each line.
# The script splits each domain into its component parts (TLD, domain, subdomain ...)
# Each segment of a domain has its string length calculated and converted to hex.
# If the segment is less than or equal to 0xf, this is converted to "0f" (padded with a zero, since snort rules expect this)
# The hexidecmal letter is converted to upper case, and the rule is written to a file.
# after the rule is written the SID number is incremented by 1 for the next rule.

rules_out_file = open(args.output, "w")
domains_in_file = open(args.input, "r")
sid = args.sid

for line in domains_in_file:
    domain = line.rstrip()

    # skip empty lines
    if domain == "":
        continue

    rule_string = snort_dns(domain, sid, args.message, args.reference)

    rules_out_file.write(rule_string)

    sid += 1
