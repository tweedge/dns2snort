#!/usr/bin/python3
import argparse
import textwrap
import re

description = """Given a file containing a list of FQDNs, quickly generate Snort rules for those domains.\n
Brought to you by @da_667, @botnet_hunter, @3XPlo1T2, and tweedge."""

parser = argparse.ArgumentParser(description=description)

parser.add_argument(
    "-i",
    dest="infile",
    required=True,
    help="The name of the file containing a list of domains, One domain per line.",
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
parser.add_argument(
    "-w",
    dest="www",
    required=False,
    action="store_true",
    help="Remove the 'www' subdomain from domains that have it.",
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
# The script calculates the segments of the domain in question (can handle 1-4 segments -- e.g. .ru (1 segments, TLD) all the way to this.is.evil.ru (4 segments))
# Each segment of a domain has it's string length calculated and converted to hex.
# If the segment is less than or equal to 0xf, this is converted to "0f" (padded with a zero, since snort rules expect this)
# The hexidecmal letter is converted to upper case, and the rule is written to a file.
# after the rule is written the SID number is incremented by 1 for the next rule.

with open(args.outfile, "w") as rules_out_file:
    with open(args.infile, "r") as domains_in_file:
        for line in domains_in_file:
            domain = line.rstrip()
            if args.www == True:
                domain = re.sub("^www\.", "", domain, flags=re.IGNORECASE)
            segment = domain.split(".")
            # try/except fixes a bug with TLD rule creation where segment has 2 elements and element 0 is '' for some reason.
            try:
                segment.remove("")
            except ValueError:
                pass
            if len(segment) == 1:
                sega = (hex(len(segment[0])))[2:]
                if int(len(sega)) == 1:
                    sega = "0%s" % sega
                rule = (
                    'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BLACKLIST DNS domain %s"; flow:to_server; byte_test:1,!&,0xF8,2; content:"|%s|%s|00|"; fast_pattern:only; metadata:service dns;  sid:%s; rev:1;)\n'
                    % (domain, sega.upper(), segment[0], args.sid)
                )
                rules_out_file.write(rule)
                print(rule)
                args.sid += 1
            elif len(segment) == 2:
                sega = (hex(len(segment[0])))[2:]
                if int(len(sega)) == 1:
                    sega = "0%s" % sega
                segb = (hex(len(segment[1])))[2:]
                if int(len(segb)) == 1:
                    segb = "0%s" % segb
                rule = (
                    'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BLACKLIST DNS domain %s"; flow:to_server; byte_test:1,!&,0xF8,2; content:"|%s|%s|%s|%s|00|"; fast_pattern:only; metadata:service dns;  sid:%s; rev:1;)\n'
                    % (
                        domain,
                        sega.upper(),
                        segment[0],
                        segb.upper(),
                        segment[1],
                        args.sid,
                    )
                )
                rules_out_file.write(rule)
                print(rule)
                args.sid += 1
            elif len(segment) == 3:
                sega = (hex(len(segment[0])))[2:]
                if int(len(sega)) == 1:
                    sega = "0%s" % sega
                segb = (hex(len(segment[1])))[2:]
                if int(len(segb)) == 1:
                    segb = "0%s" % segb
                segc = (hex(len(segment[2])))[2:]
                if int(len(segc)) == 1:
                    segc = "0%s" % segc
                rule = (
                    'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BLACKLIST DNS domain %s"; flow:to_server; byte_test:1,!&,0xF8,2; content:"|%s|%s|%s|%s|%s|%s|00|"; fast_pattern:only; metadata:service dns;  sid:%s; rev:1;)\n'
                    % (
                        domain,
                        sega.upper(),
                        segment[0],
                        segb.upper(),
                        segment[1],
                        segc.upper(),
                        segment[2],
                        args.sid,
                    )
                )
                rules_out_file.write(rule)
                print(rule)
                args.sid += 1
            elif len(segment) == 4:
                sega = (hex(len(segment[0])))[2:]
                if int(len(sega)) == 1:
                    sega = "0%s" % sega
                segb = (hex(len(segment[1])))[2:]
                if int(len(segb)) == 1:
                    segb = "0%s" % segb
                segc = (hex(len(segment[2])))[2:]
                if int(len(segc)) == 1:
                    segc = "0%s" % segc
                segd = (hex(len(segment[3])))[2:]
                if int(len(segd)) == 1:
                    segd = "0%s" % segd
                rule = (
                    'alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BLACKLIST DNS domain %s"; flow:to_server; byte_test:1,!&,0xF8,2; content:"|%s|%s|%s|%s|%s|%s|%s|%s|00|"; fast_pattern:only; metadata:service dns;  sid:%s; rev:1;)\n'
                    % (
                        domain,
                        sega.upper(),
                        segment[0],
                        segb.upper(),
                        segment[1],
                        segc.upper(),
                        segment[2],
                        segd.upper(),
                        segment[3],
                        args.sid,
                    )
                )
                print(rule)
                rules_out_file.write(rule)
                args.sid += 1
            else:
                print(
                    "the number of segments in the domain %s is greater than 4. Skipping."
                    % domain
                )
                pass
