# quickburn

[![Code Style](https://img.shields.io/badge/code%20style-black-black)](https://github.com/psf/black)

Given a file containing a list of fully qualified DNS domains, generate Snort rules for those domains. Incredibly useful if you are sitting on top of a pile of IOCs, but want an efficiently lazy way to generate Snort signatures for them.

### Kudos

This project is originally by [da667](https://github.com/da667), with contributions from @botnet_hunter, and @3XPlo1T2.

### Example

This script supports TLDs and FQDNs - see the example below, or try the sampledns.txt and sample.rules files provided with this repository.

**Example input:**

```
.pw
evilcorp.co
www.evil.com
seemstoteslegit.notreally.tk
stupidlylongsubdomain.lol.wutski.biz
```

**...becomes:**

```
alert udp $HOME_NET any -> any 53 (msg:"dns2snort banned DNS domain .pw"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|02|pw|00|"; nocase; distance:0; fast_pattern; metadata:service dns; sid:1000000; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"dns2snort banned DNS domain evilcorp.co"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|08|evilcorp|02|co|00|"; nocase; distance:0; fast_pattern; metadata:service dns; sid:1000001; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"dns2snort banned DNS domain www.evil.com"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|03|www|04|evil|03|com|00|"; nocase; distance:0; fast_pattern; metadata:service dns; sid:1000002; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"dns2snort banned DNS domain seemstoteslegit.notreally.tk"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|0F|seemstoteslegit|09|notreally|02|tk|00|"; nocase; distance:0; fast_pattern; metadata:service dns; sid:1000003; rev:1;)
alert udp $HOME_NET any -> any 53 (msg:"dns2snort banned DNS domain stupidlylongsubdomain.lol.wutski.biz"; content:"|01|"; offset:2; depth:1; content:"|00 01 00 00 00 00 00|"; distance:1; within:7; content:"|15|stupidlylongsubdomain|03|lol|06|wutski|03|biz|00|"; nocase; distance:0; fast_pattern; metadata:service dns; sid:1000004; rev:1;)
```

These are all properly formatted Snort rules ready to be pushed to a sensor.

### Notes

* Please note that none of these sample domains are malicious. They are samples for testing only.
* Some additional changes have been made from da_667's version of dns2snort, these are:
  * The subdomain limitation has been removed.
  * There is no longer an argument to allow removing `www.` from domains.
  * `idstools` now does a basic check on the validity of the produced rule
  * Custom metadata can be optionally added to the rule