# Firewall Bash Script

## Team 37
- **Name** Adam Giaourtas 
    - **AM** 2019030106
- **Name** Alexandros Goridaris 
    - **AM** 2019030108

## Overview
This is a simple firewall bash script that rejects packets coming from specific network domains or IP addresses.

## Implementation
This tool is using the `iptables/ip6tables` commands to configure firewall rules based on domain names and IP addresses provided by `config.txt`. The command-line tool `dig` is used to resolve the IPv4 and IPv6 addresses of specified domains. Firewall rules can be saved/loaded from rulesV4 and rulesV6 files.

## Question
>After configuring the firewall rules, test your script by visiting your favorite websites without any other adblocking mechanism (e.g., adblock browser extensions). Can you see ads? Do they load? Some ads persist, why?

Ad count was significantly lower after configuring the firewall rules, especially on sketchy websites. Also, the domains listed on the config file didn't load, when visited. Some ads did persist because config list doesn't include all ad-serving domains. What's more, ads could be embedded within website content.

## Tool Specification

The tool accepts the following command-line arguements:
- `-config` : Configure firewall rules from config.txt.
- `-save` : Save rules to rulesV4 and rulesV6 files.
- `-load` : Load rules from rulesV4 and rulesV6 files.
- `-list` : List current rules.
- `-reset` : Reset rules to default.
- `-help` : Help message. 

```bash
sudo ./firewall.sh [-arguement]
```