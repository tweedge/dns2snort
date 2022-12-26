#!/usr/bin/python3
import argparse

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

    filter = "alert udp $HOME_NET any -> $EXTERNAL_NET 53"
    message = f'msg:"BLACKLIST DNS domain {domain}";'
    detect = f'flow:to_server; byte_test:1,!&,0xF8,2; content:"{content}|00|"; fast_pattern:only;'
    metadata = f"metadata:service dns; sid:{sid}; rev:1;"

    rule = f"{filter} ({message} {detect} {metadata})\n"
    rules_out_file.write(rule)

    sid += 1
