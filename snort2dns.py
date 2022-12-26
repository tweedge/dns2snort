#!/usr/bin/python3
import argparse

description = "Given a file containing a list of Snort rules, extract any blocked domains."

parser = argparse.ArgumentParser(description=description)

parser.add_argument(
    "-i",
    dest="infile",
    required=True,
    help="The name of the file containing a list of Snort rules, one rule per line.",
)
parser.add_argument(
    "-o",
    dest="outfile",
    required=True,
    help="The name of the file to output domains to.",
)
args = parser.parse_args()

rules_in_file = open(args.infile, "r")
domains_out_file = open(args.outfile, "w")

for line in rules_in_file:
    rule = line.strip()

    # skip empty lines
    if rule == "":
        continue

    if not "metadata:service dns" in rule:
        continue

    if not "flow:to_server" in rule:
        continue

    # slice the rule to get only the content
    first_slice = rule.split('content:"')
    second_slice = first_slice[1].split('";')
    content = second_slice[0]

    segments = content.split("|")
    domain = ""

    skip = False
    for segment in segments:
        # read every other value (content, not length)
        if skip:
            skip = False
            continue
        skip = True

        if segment == "":
            continue

        domain += f"{segment}."

    domain = domain.strip(".")
    domains_out_file.write(f"{domain}\n")
