# dns2snort

[![Code Style](https://img.shields.io/badge/code%20style-black-black)](https://github.com/psf/black)

Given a file containing a list of fully qualified DNS domains, generate Snort rules for those domains. Incredibly useful if you are sitting on top of a pile of IOCs, but want an efficiently lazy way to generate Snort signatures for them.

### Kudos

This project is originally by [da_667](https://github.com/da667), with contributions from @botnet_hunter, and @3XPlo1T2.

### Example

This script supports TLDs, and FQDNs up to four subdomains deep - see the example below, in addition to the sampledns.txt and sample.rules files provided with this script.

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
alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BLACKLIST DNS domain .pw"; flow:to_server; byte_test:1,!&,0xF8,2; content:"|02|pw|00|"; fast_pattern:only; metadata:service dns;  sid:1000000; rev:1;)
alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BLACKLIST DNS domain evilcorp.co"; flow:to_server; byte_test:1,!&,0xF8,2; content:"|08|evilcorp|02|co|00|"; fast_pattern:only; metadata:service dns;  sid:1000001; rev:1;)
alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BLACKLIST DNS domain www.evil.com"; flow:to_server; byte_test:1,!&,0xF8,2; content:"|03|www|04|evil|03|com|00|"; fast_pattern:only; metadata:service dns;  sid:1000002; rev:1;)
alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BLACKLIST DNS domain seemstoteslegit.notreally.tk"; flow:to_server; byte_test:1,!&,0xF8,2; content:"|0F|seemstoteslegit|09|notreally|02|tk|00|"; fast_pattern:only; metadata:service dns;  sid:1000003; rev:1;)
alert udp $HOME_NET any -> $EXTERNAL_NET 53 (msg:"BLACKLIST DNS domain stupidlylongsubdomain.lol.wutski.biz"; flow:to_server; byte_test:1,!&,0xF8,2; content:"|15|stupidlylongsubdomain|03|lol|06|wutski|03|biz|00|"; fast_pattern:only; metadata:service dns;  sid:1000004; rev:1;)
```

These are all properly formatted Snort rules ready to be pushed to a sensor.

### Notes

* Please note that none of these sample domains are malicious. They are samples for testing only.
* The domain list input file should not have ANY trailing spaces on any of the individual user-agent lines. Additionally, there should be ZERO blank lines in the domain list file that will be used to generate the snort rules. If the script encounters any FQDNs greater than 4 subdomains deep (such as "lol.wut.you.doin.it [5-level subdomain]") the script will skip over them, notify the user, and print it to the terminal. 
* If you think this is a concern, the Mandiant APT1 report has over 2000 domains as IOCs associated with the campaign. dns2snort only encountered two FQDNs with 5+ subdomains; dns2snort successfully created rules for every other domain in the list of IOCs. Maybe you can look over my code and implement a way to support FQDNs of varying length? I'm not good enough at python to do this currently without a huge CF of if/then statements. Help is welcome.
