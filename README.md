# quickburn

[![Code Style](https://img.shields.io/badge/code%20style-black-black)](https://github.com/psf/black)

Given a file containing a list of fully qualified DNS domains, quickburn generates IDS rules which detect those domains (and their subdomains) in DNS queries, the HTTP Host header, or TLS SNI (or all of the above!). quickburn supports Snort, Suricata 4, and Suricata 5, and tries to use the most efficient methods available for each option.

### Why?

If you publish IOCs independently, it's pretty much a crapshoot if those IOCs will get picked up and integrated into security products that can protect people. If you generate and submit signatures to [Emerging Threats](https://rules.emergingthreats.net/) using quickburn, you can contribute useful day-one defenses which are consumed by thousands or millions of networks around the world, such as networks using:

* pfSense and opnSense (if IDS is configured)
* Ubiquiti security gateways
* Synology routers

...and many others. quickburn could also introduce more people to contributing to Emerging Threats.

### Usage

quickburn is a Python script which uses command line options, and should support any OS.

```
% git clone https://github.com/tweedge/quickburn
% cd quickburn
% python3 quickburn.py --help
```

#### Required Arguments

* **--input <file_name>** - The name of the file containing a list of domains, one domain per line
* **--output <folder_name>** - The name of the folder to output your IDS rules to

#### Generation Flags

One or more of the below is required:

* **--dns** - Generate IDS rules to find domains in DNS queries
* **--http** - Generate IDS rules to find domains in HTTP host headers
* **--tls** - Generate IDS rules to find domains in TLS SNI fields

#### Optional Arguments

* **--sid <integer>** - Optional: The rule ID to start numbering incrementally at (default is 1000000, must be between 1000000-2000000)
* **--reason <text>** - Optional: A custom reason to include in each rule's message (ex. "ViperSoftX CnC")
* **--reference <text>** - Optional: A URL to include as a reference in each rule (ex. a research article)

#### Outputs

The output rules will be sorted by what IDS they support, ex:

```
foldername/
  snort.rules
  suricata4.rules
  suricata5.rules
```

Each output file has one rule per line for that IDS. If you're submitting rules to Emerging Threats, submit all of these to save the ET staff time converting rules between each IDS manually.

### Kudos

This project is based on [dns2snort](https://github.com/da667/dns2snort), which is originally by [da667](https://github.com/da667) (with contributions from @botnet_hunter and @3XPlo1T2).

### Notes

* Please note that none of the sample domains in `sample/` are malicious. They are samples for testing only.
* Several changes have been made from da667's dns2snort script. quickburn is not backwards compatile.