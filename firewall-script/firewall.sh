#!/bin/bash
# You are NOT allowed to change the files' names!
config="config.txt"
rulesV4="rulesV4"
rulesV6="rulesV6"

function firewall() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-config"  ]; then
        # Configure firewall rules based on domain names and IPs of $config file.
       
        while IFS= read -r line; do

            line=$(echo "$line" | xargs) 

            if [[ $line =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                echo "Blocking IPv4: $line"
                sudo iptables -A INPUT -s "$line" -j REJECT
                sudo iptables -A OUTPUT -s "$line" -j REJECT

            elif [[ $line =~ : ]]; then
                echo "Blocking IPv6: $line" 
                sudo ip6tables -A INPUT -s "$line" -j REJECT
                sudo ip6tables -A OUTPUT -s "$line" -j REJECT

            else 
                echo "Resolving domain: $line"

                ip4_addrs=$(dig +short "$line" A | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
                for ip in $ip4_addrs; do
                    echo "Blocking IPv4: $ip" 
                    sudo iptables -A INPUT -s "$ip" -j REJECT
                    sudo iptables -A OUTPUT -s "$ip" -j REJECT

                done

                ip6_addrs=$(dig +short "$line" AAAA | grep -E "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$")
                for ip in $ip6_addrs; do
                    echo "Blocking IPv6: $ip" 
                    sudo ip6tables -A INPUT -s "$ip" -j REJECT
                    sudo ip6tables -A OUTPUT -s "$ip" -j REJECT

                done
            fi

        done < "$config"

    elif [ "$1" = "-save"  ]; then
        # Save rules to $rulesV4/$rulesV6 files.
        echo "Saving rules..."
        sudo iptables-save > rulesV4
        echo "IPv4 rules saved to file $rulesV4."
        sudo ip6tables-save > rulesV6
        echo "IPv6 rules saved to file $rulesV6."
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $rulesV4/$rulesV6 files.
        echo "Loading rules..."
        sudo iptables-restore < rulesV4
        echo "IPv4 rules loaded from file $rulesV4."
        sudo ip6tables-restore < rulesV6
        echo "IPv6 rules loaded from file $rulesV6."
        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset IPv4/IPv6 rules to default settings (i.e. accept all).
        echo "Resetting IPv4/IPv6 rules to default settings..."
        sudo iptables -F INPUT
        sudo iptables -F OUTPUT
        sudo iptables -P INPUT ACCEPT
        sudo iptables -P OUTPUT ACCEPT
        sudo ip6tables -F INPUT
        sudo ip6tables -F OUTPUT
        sudo ip6tables -P INPUT ACCEPT
        sudo ip6tables -P OUTPUT ACCEPT
        echo "Reset complete."
        true

        
    elif [ "$1" = "-list"  ]; then
        # List IPv4/IPv6 current rules.
        sudo iptables -L 
        sudo ip6tables -L
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple firewall mechanism. It rejects connections from specific domain names or IP addresses using iptables/ip6tables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -config\t  Configure adblock rules based on the domain names and IPs of '$config' file.\n"
        printf "  -save\t\t  Save rules to '$rulesV4' and '$rulesV6'  files.\n"
        printf "  -load\t\t  Load rules from '$rulesV4' and '$rulesV6' files.\n"
        printf "  -list\t\t  List current rules for IPv4 and IPv6.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

firewall $1
exit 0