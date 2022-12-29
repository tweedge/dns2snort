#!/usr/bin/python3
import argparse
from idstools import rule

description = """Given a file containing a list of FQDNs, quickly generate Snort rules for those domains.\n
Brought to you by @da_667, @botnet_hunter, @3XPlo1T2, and tweedge."""

parser = argparse.ArgumentParser(description=description)

parser.add_argument(
    "-i",
    dest="infile",
    required=True,
    help="The name of the file containing a list of domains, one domain per line.",
)
parser.add_argument(
    "-o",
    dest="outfile",
    required=True,
    help="The name of the file to output your Snort rules to.",
)
parser.add_argument(
    "-s",
    dest="sid",
    type=int,
    required=True,
    help="The Snort SID to start numbering incrementally at. This number should be between 1000000 and 2000000.",
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

rules_out_file = open(args.outfile, "w")
domains_in_file = open(args.infile, "r")
sid = args.sid

for line in domains_in_file:
    domain = line.rstrip()

    # skip empty lines
    if domain == "":
        continue

    segments = domain.split(".")

    # remove blank strings in index 0 (ex. where ".tld" is split into ["", "tld"])
    if segments[0] == "":
        segments = segments[1:]

    content = ""
    for segment in segments:
        segment_len_hex = hex(len(segment))[2:]
        if len(segment_len_hex) == 1:
            segment_len_hex = "0%s" % segment_len_hex
        content += f"|{segment_len_hex.upper()}|{segment}"
    content = f'"{content}|00|"'

    filter = "alert udp $HOME_NET any -> any 53"
    message = f'msg:"dns2snort banned DNS domain {domain}";'
    dns_queries_only = 'content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7;'
    detect = f'content:{content}; nocase; distance:0; fast_pattern;'
    metadata = f"metadata:service dns; sid:{sid}; rev:1;"

    rule_string = f"{filter} ({message} {dns_queries_only} {detect} {metadata})\n"
    parsed_rule = rule.parse(rule_string)
    if parsed_rule.content == content:
        rules_out_file.write(rule_string)
    else:
        print("idstools detected different content than what was expected, skipping")
        print(f"Expected: {content}")
        print(f"Received: {parsed_rule.content}")

    sid += 1
