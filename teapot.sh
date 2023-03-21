#!/bin/bash
###############################
#Author = blueSky
#Last edited October 3, 2022
###############################
# install teapot
# 1. git clone https://github.com/SkysNotes/teapot/blob/main/teapot.sh /opt/teapot.sh
# 2. ln -s ~/opt/teapot.sh /usr/bin/teapot

# isntall parcenmap
# 1. git clone https://github.com/R3dy/parsenmap /opt/parcenmap
# 2. cd parcenmap
# 3. bundle install
# 4. ln -s ~/opt/parsenmap/parsenmap.rb /usr/bin/parsenmap 

# TODO: add other tool sources and instalation manuals
# sudo apt-get install sshpass
# sudo apt-get install html2text
# sudo apt install parsero
# sudo apt install gobuster
# sudo apt install seclists
# sudo apt install smtp-user-enum
# pip install droopescan

RED="\e[31m"
GREEN="\e[32m"
BLUE="\e[1;94m"
ENDCOLOR="\e[0m"

# default nmap user list
users_lst="/usr/share/wordlists/metasploit/unix_users.txt"
roots_lst="/usr/share/wordlists/metasploit/common_roots.txt"
# default nmap passw list
host_lst="host.lst"
pass_lst="/root/SecLists/Passwords/10_million_password_list_top_100.txt"

create_folders () {
    if [ ! -d "$1" ];then
        mkdir "$1"
    fi
}

create_folders "discovery"
create_folders "discovery/hosts"
create_folders "discovery/services"
create_folders "discovery/services/service_list"
create_folders "discovery/services/service_vulns"


# └── pen_test_target_folder
#     ├── discovery
#     │   ├── hosts
#     │   │   ├── targets.txt
#     │   ├── ranges.txt
#     │   └── services
#     │       ├── service_vulns
#     │       |    ├── 10_110_115_75
#     │       |    |    ├── ssh.vulns
#     │       |    |    ├── http.vulns
#     │       |    |    ├── http.cgi.list
#     │       |    |    ├── http.cgi.html_text_1
#     │       |    |    ├── http.cgi.html_text_2
#     │       |    ├── 10_110_115_77
#     │       |    |    ├── mssql.vulns
#     │       |    |    ├── http.vulns
#     │       ├── service_list
#     │       |    ├── mssql
#     │       |    ├── http
#     │       |    ├── ssh
#     │       ├── all_ports.csv
#     │       └── full_sweep.xml
#     ├── documentation
#     │   ├── logs
#     │   └── screenshots
#     └── focused_penetration


ping_sweep="discovery/hosts/ping_sweep.txt"
temp_file="discovery/hosts/t.txt"
targets="discovery/hosts/targets.txt"
full_sweep="discovery/services/full_sweep"
top_10_ports="discovery/services/top_10_ports.txt"
all_ports="discovery/services/all_ports.csv"
service_list="discovery/services/service_list"

PROXY=""
PORTS=""


call_header () {
    if [ "$1" != "" ]; then
    echo -e "${BLUE}++++++++++++++++++++++++++++++++++++++++++++++++++${ENDCOLOR}"
        echo -e "${BLUE}[+] $1"
        if [ "$2" != "" ]; then
            echo -e "${BLUE}[+] $2${ENDCOLOR}"
        fi
    echo -e "${BLUE}++++++++++++++++++++++++++++++++++++++++++++++++++${ENDCOLOR}"
    fi
}


call_header2 () {
    if [ "$1" != "" ]; then
        echo -e "${BLUE}$1${ENDCOLOR}"
        if [ "$2" != "" ]; then
            echo -e "${BLUE}$2${ENDCOLOR}"
        fi
    echo -e "${BLUE}..................................................${ENDCOLOR}"
    fi
}


Object () {
  kind=$1
  self=$2

  # iterates over the remaining args
  for arg in "$@"; do
    # e.g name=Robert -> ARG_KEY=name ARG_VALUE=Robert
    read -r ARG_KEY ARG_VALUE <<< "$(echo "$arg" | sed -E "s/(\w+)=(.*?)/\1 \2/")"
    read -r FUNC <<< "$(echo "$arg" | sed -E "s/fn_(\w+)$/\1/")"
    if [[ -n "$ARG_KEY" ]] && [[ -n "$ARG_VALUE" ]]; then
        # declare the object's state
        export "${self}_$ARG_KEY"="$ARG_VALUE" 
    elif [[ -n "$FUNC" ]] && [[ "$FUNC" != "$self" ]]; then
        ## Define the function in the global scope, prepending the object kind, e.g account_fn_display, user_fn_logout etc
        export "${kind}_fn_$FUNC=$FUNC"
        # export "fn_$FUNC=$FUNC"
    fi
  done
}

display () {
    self=$1
    local list=${self}_list
    local command=${self}_command
    local file=${self}_file
    local pipe=${self}_pipe


    while IFS="" read -r p || [ -n "$p" ]
    do
    if [ "$p" != "" ]; then
        target_ip="$(echo "$p" |cut -d$'\t' -f1)"
        port="$(echo "$p" |cut -d$'\t' -f2)"
        service="$(echo "$p" |cut -d$'\t' -f3)"
        folder="$(echo "$target_ip" | sed "s/[.]/_/g")"
        target_folder="discovery/services/service_vulns/$folder"
        create_folders "$target_folder"
        tee_output="tee -a $target_folder/$service.${!file}" 


        if [ "$PROXY" != '' ]; then
            echo "proxy: $PROXY" 
            exec_command="$PROXY ${!command} 2>/dev/null ${!pipe}"
        else 
            exec_command="${!command} ${!pipe}"
        fi

        sleep .5
        call_header2 "$exec_command" |& $tee_output
        eval "$exec_command" |& $tee_output
        wait -n
        printf "\n\n"|& $tee_output
    fi
    done < "${!list}"
}

displayNetwork() {
    self=$1
    local ipAddr=${self}_ipAddr
    local command=${self}_command
    local file=${self}_file
    local pipe=${self}_pipe

    tee_output="tee -a ${!file}" 

# "sudo nmap --top-ports=10 $ip_addr -sS -Pn --open > $top_10_ports"
    if [ "$PROXY" != '' ]; then
        echo "proxy: $PROXY" 
        exec_command="sudo $PROXY ${!command} ${!ipAddr} ${!pipe} 2> /dev/null"
    else 
        exec_command="${!command} ${!ipAddr} ${!pipe}"
    fi

    sleep .5
    call_header2 "$exec_command"
    eval "$exec_command" |& $tee_output
    wait -n
    printf "\n\n"
}


#-----------------NETWORK-------------------#
# ICMP ping of subnet
ping_all_hosts () {
    ip_addr=$1
    call_header "Pinging all 1-254 hosts with PING..."
    for host in {1..254}; do ping -c 1 "$ip_addr" -W 1 >> $ping_sweep & done
    ( grep "bytes from" | cut -d " " -f4 | cut -d ":" -f1 | sort -u )< "$ping_sweep" > "$temp_file"
    cat "$temp_file"
    printf "\n\n"
}

# getting more hosts without ICMP
ping_all_hosts_without_ICMP () {
    ip_addr=$1
    call_header "Performing host dicovery enumeration without ICMP request with NMAP..."
    local nmap_scan="sudo nmap $ip_addr -sn -vv --min-rate 1000 --max-retries 2 > $ping_sweep"
    echo "$nmap_scan"
    eval "$nmap_scan"

    # filtering the output and saving to $targets
    (grep Up hosts |cut -d " " -f2)< "$ping_sweep" >> "$temp_file"
    sort -u < "$temp_file" > "$targets"
    sudo rm "$temp_file"
    printf "Final target list:\n"
    cat $targets
    printf "\n\n"
}

# scanning top 10 ports
scan_top_10_ports () {
    ip_addr=$1
    call_header "Performing nmap scan for top-10-ports..."
    Object network topPorts ipAddr="$ip_addr" command='nmap --top-ports=10 -sT -Pn --open' file="$top_10_ports" fn_displayNetwork 
    $network_fn_displayNetwork topPorts

    # filtering the output and saving to $targets
    grep -oP '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'< "$top_10_ports" >> "$temp_file"
    (grep -v '127.0.0.1'| sort -u) < "$temp_file" > "$targets"
    # sudo rm "$temp_file"
    printf "\n\n"
}

# TODO: add UDP scan? https://github.com/superkojiman/onetwopunch/blob/master/onetwopunch.sh

# full sweep scan
perform_full_sweep_scan(){
    call_header "Scanning all ports for all targets with NMAP..."
    # TODO: sudo nmap 10.11.1.50 -T5 -p- -sV -sC
    if [ "$PROXY" != '' ]; then
        if [ "$PORTS" != '' ]; then
            Object network fullScan command='nmap -sT -Pn -A --open -p"$PORTS" -oA "$full_sweep" -iL "$targets"' fn_displayNetwork 
        else
            Object network fullScan command='nmap --top-ports=1000 -A -sT -Pn --open -oA "$full_sweep" -iL "$targets"' fn_displayNetwork 
        fi  
    else
        if [ "$PORTS" != '' ]; then
            Object network fullScan command='nmap -Pn -A --open -p"$PORTS" -oA "$full_sweep" -iL "$targets"' fn_displayNetwork 
        else
            Object network fullScan command='nmap -Pn -A -p 0-65535 T5 -oA "$full_sweep" -iL "$targets"' fn_displayNetwork 
        fi
    fi
    # Object network fullScan command='sudo nmap -sV -sC -p 0-65535 T5 -oA "$full_sweep" -iL "$targets"' fn_displayNetwork 
    $network_fn_displayNetwork fullScan
    # local nmap_scan="sudo nmap -Pn -n -p 0-65535 -iL $targets -sV -A --min-rate 50000 --min-hostgroup 22 -oA $full_sweep"
}

# parcing scan data and extracting to files
extract_data () {
    full_sweep_file="$full_sweep.xml"
    if [ -n "$1" ]; then
    full_sweep_file=$1 
    fi
    
    call_header "Extracting data from full_sweep..."

    parsenmap "$full_sweep_file" | sed 's/sudo.*//' > $all_ports
    cat $all_ports

    while IFS="" read -r p || [ -n "$p" ]
    do
        if [ "$p" != "" ]; then
        service="$(echo "$p" |cut -d$'\t' -f3)"
        echo "$p" >> "$service_list"/"$service"
        printf "\n\n"
    fi
    done < $all_ports
}

#-----------------VULNS-------------------#
scan_DNS () {
    # domain enumeration
    call_header "dns enumeration..."
    Object dns hostlookup list="$list" command='host -l thinc.local "$target_ip"' file="dnslookup" fn_display 
    $dns_fn_display hostlookup

}

scan_SMB () {
    list=$1

    # scanning smb with nmblookup
    call_header "Scaning with nmblookup..."
    Object smb nmblookup list="$list" command='nmblookup -A "$target_ip"' file="nmblookup" fn_display 
    $smb_fn_display nmblookup

    # scanning smb with nbtscan
    call_header "Scaning with nbtscan..."
    Object smb nbtscan list="$list" command='nbtscan "$target_ip"' file="nbtscan" fn_display 
    $smb_fn_display nbtscan

    # scanning smb with enum4linux
    call_header "Scaning with enum4linux..."
    Object smb enum4linux list="$list" command='enum4linux -a -o "$target_ip"' file="enum4linux" fn_display 
    $smb_fn_display enum4linux

    # scanning smb with smbmap
    call_header "Scaning with smbmap..."
    Object smb smbmap list="$list" command='smbmap -H "$target_ip" -v -P "$port"' file="vulns" fn_display 
    $smb_fn_display smbmap

    # scanning with crackmapexec
    call_header "Scaning with crackmapexec..."
    Object smb crackmapexec list="$list" command='crackmapexec smb "$target_ip"' file="vulns" fn_display 
    $smb_fn_display crackmapexec
    
    # enumerating smb shares with nmap
    call_header "Enumerating shares - SMB..."
    Object smb enumShares list="$list" command='nmap -Pn -sT --open --script smb-enum-shares,smb-os-discovery "$target_ip" -p "$port"' file="shares" fn_display 
    $smb_fn_display enumShares

    # scanning smb for vulns with nmap
    call_header "Scanning for vulns - SMB..."
    Object smb smbVulns list="$list" command='nmap -sV -Pn -v -n --script smb-vuln-ms17-010,smb-vuln-cve-2017-7494 "$target_ip" -p "$port"' file="vulns" fn_display 
    $smb_fn_display smbVulns

    # enumerating smb users with nmap
    call_header "Enumerating users - SMB..."
    Object smb smbVulns2 list="$list" command='nmap --script smb-enum-users -p "$port" "$target_ip"' file="vulns" fn_display 
    $smb_fn_display smbVulns2


} 

scan_FTP () {
    list=$1

    # fingerprinting ftp with netcat
    call_header "Checking for FTP version ..."
    Object ftp vulns list="$list" command='nc -nv -w 1 "$target_ip" "$port"' file="vulns" fn_display 
    $ftp_fn_display vulns

    # trying to loging with with ftp anonymous: anonymous
    call_header "Attemping to login as anonymous - FTP,TFTP..."
    Object ftp anonLog list="$list" command='ftp ftp://anonymous:anonymous@"$target_ip:$port"' file="vulns" fn_display 
    $ftp_fn_display anonLog

    # scanning for vulns with nmap
    call_header "Scanning for FTP vulns with nmap ..."
    Object ftp vulns list="$list" command='nmap --script ftp-vuln* -Pn -sV "$target_ip" -p"$port"' file="vulns" fn_display 
    $ftp_fn_display vulns

}

scan_SSH () {
    list=$1

    call_header "Banner grabbing with dmitry - SSH..."
    Object ssh vulns list="$list" command=' dmitry -bp "$target_ip"' file="vulns" fn_display 
    $ssh_fn_display vulns

    # scanning with crackmapexec
    call_header "Scaning with crackmapexec..."
    Object ssh crackmapexec list="$list" command='crackmapexec ssh "$target_ip"' file="vulns" fn_display 
    $ssh_fn_display crackmapexec

    # Performing ssh fingerprint and bunner grabbing with nmap
    call_header "Performing ssh fingerprint and bunner grabbing with nmap ..."
    Object ssh vulns list="$list" command='nmap --script=ssh-auth-methods,ssh-hostkey -sV -Pn -p "$port" "$target_ip"' file="vulns" fn_display 
    $ssh_fn_display vulns

    # Scanning for SSH package version
    call_header "Scanning for SSH package version..."
    Object ssh sshVersion list="$list" command='nc -nv "$target_ip" "$port" -q 5' file="vulns" fn_display 
    $ssh_fn_display sshVersion
    printf "NOTE: Check https://packages.ubuntu.com/search?keywords=openssh-server for linux version based on ssh version"
    printf "\n\n"

    # Trying SSH login with credentials 'anonymous:anonymous'
    call_header "Trying SSH login with credentials 'anonymous:anonymous'..."
    Object ssh sshFingerprint list="$list" command='sshpass -p anonymous ssh anonymous@"$target_ip" -tt -o "StrictHostKeyChecking=accept-new"' file="vulns" fn_display 
    $ssh_fn_display sshFingerprint
    printf "NOTE: If you don't see the 'Warning: Permanently added...', you have the ssh-key already\n"
    printf "NOTE: Check for https://github.com/rapid7/ssh-badkeys"
    printf "\n\n"
    printf "NOTE: Recommend SSH brute force tools: A custom wordlist for the target (using another vulnerability or CeWL/wordhound), Hydra (don't forget about '-e [VALUES]'), Patator (Password fuzzer rather than brute force), Crowbar (great for brute forcing private keys), Metasploit's ssh_login."
    printf "\n\n"
}

scan_TELNET () {
    list=$1

    # Scanning for vulns with nmap- TELNET
    call_header "Scanning for vulns - TELNET..."
    Object telnet vulns list="$list" command='nmap --script telnet-ntlm-info -Pn -sV "$target_ip" -p"$port"' file="vulns" fn_display 
    $telnet_fn_display vulns

    echo "You may bruteforce TELNET: hydra -l root -P target_ip"
    printf "\n\n"
}

scan_SMTP () {
    list=$1

    # Banner grabbing with nmap
    call_header "Banner grabbing - SMTP..."
    Object smtp vulns list="$list" command='nmap -sV "$target_ip" -p"$port"' file="vulns" fn_display 
    $smtp_fn_display vulns

    # smtp-ntlm-info.nse,smtp-open-relay.nse

    # scanning SMTP for vulns with nmap
    call_header "Scanning for vulns - SMTP..."
    Object smtp vulns list="$list" command='nmap --script smtp-vuln* -Pn -sV "$target_ip" -p"$port"' file="vulns" fn_display 
    $smtp_fn_display vulns

    # Enumerating SMTP with nmap
    call_header "Scanning for vulns - SMTP..."
    Object smtp vulns list="$list" command='nmap --script smtp-commands,smtp-enum-users -Pn -sV "$target_ip" -p"$port"' file="vulns" fn_display 
    $smtp_fn_display vulns

    # enumerating SMTP with smtp-user-enum
    call_header "Enumerating users - SMTP..."
    Object smtp vulns list="$list" command='smtp-user-enum -M VRFY -U "$roots_lst" -t "$target_ip"' file="vulns" fn_display 
    $smtp_fn_display vulns

}

scan_KERBEROS () {
    list=$1

    # TODO: FIX THIS
    # nmap -p 88 --script krb5-enum-users --script-args krb5-enum-users.realm='test'
    # https://github.com/ropnop/kerbrute

    # call_header "Scanning for vulns - KERBEROS..."
    # Object smtp vulns list="$list" command='nmap --script smb-vuln* -Pn -sV "$target_ip" -p"$port"' file="vulns" fn_display 
    # $smtp_fn_display vulns
    # nmap -sV -sC -vv -p88 --script nmap-vulners/ -iL "$list" 
    # echo "You may check MS14-068 for priv escalation"

    # printf "\n\n"
}

scan_POP3 () {
    list=$1

    # enumerating pop3 with nmap
    call_header "Enumerating with nmap - POP3..."
    Object pop3 vulns list="$list" command='nmap -sV --script pop3-capabilities,pop3-ntlm-info "$target_ip" -p"$port"' file="vulns" fn_display 
    $pop3_fn_display vulns 
}
    
scan_NFS () {
    list=$1

    call_header "Scanning for vulns - NFS..."
    Object nfs vulns list="$list" command='nmap -sV -Pn --script nfs-showmount,nfs-ls,nfs-statfs "$target_ip" -p"$port"' file="vulns" fn_display 
    $nfs_fn_display vulns
}

scan_NNTP () {
    list=$1
    call_header "Scanning for vulns - NNTP..."
    Object nntp vulns list="$list" command='nmap -sV -Pn --script ntp-monlist,ntp-info "$target_ip" -p"$port"' file="vulns" fn_display 
    $nntp_fn_display vulns
} 

scan_MSRPC () {
    list=$1

    call_header "Scanning for vulns - MSRPC..."
    Object msrpc vulns list="$list" command='nmap --script msrpc-enum -Pn "$target_ip" -p"$port"' file="vulns" fn_display 
    $msrpc_fn_display vulns

    call_header "Dumping list of rpc endpoints with rpcdump - MSRPC..."
    Object msrpc vulns list="$list" command='impacket-rpcdump "$target_ip" -port "$port"' file="vulns" fn_display 
    $msrpc_fn_display vulns

    # List system user accounts, available resource shares and other sensitive information exported through the SAMR (Security Account Manager Remote) interface.
    call_header "Dumping list of user accounts and shares with samrdump - MSRPC..."
    Object msrpc vulns list="$list" command='impacket-samrdump "$target_ip" -port "$port"' file="vulns" fn_display 
    $msrpc_fn_display vulns
}    

scan_IMAP () {
    list=$1

    call_header "Scanning for vulns - IMAP..."
    Object imap vulns list="$list" command='nmap -sV -Pn --script imap-ntlm-info,imap-capabilities "$target_ip" -p"$port"' file="vulns" fn_display 
    $imap_fn_display vulns

}

scan_SNMP () {
    list=$1
    call_header "Scanning for vulns - SNMP..."

    #snmp-brute.nse, snmp-hh3c-logins.nse, snmp-info.nse
    # snmp-interfaces.nse, snmp-ios-config.nse, snmp-netstat.nse
    # snmp-processes.nse, snmp-sysdescr.nse, snmp-win32-services.nse
    # snmp-win32-software.nse, snmp-win32-users.nse
    Object snmp vulns list="$list" command='nmap -sV -Pn --script snmp-win32-shares "$target_ip" -p"$port"' file="vulns" fn_display 
    $snmp_fn_display vulns

    Object snmp enum list="$list" command='nmap -vv -sV -sU -Pn --script=snmp-netstat,snmp-processes "$target_ip" -p"$port"' file="vulns" fn_display 
    $snmp_fn_display enum


    Object snmp vulns list="$list" command='snmp-check "$target_ip" -c public' file="vulns" fn_display 
    $snmp_fn_display vulns

    # we need to know that there is a community called public
    Object snmp vulns list="$list" command='snmpwalk -c public -v1 "$target_ip"' file="vulns" fn_display 
    $snmp_fn_display vulns

    # enumerate windows users
    Object snmp vulns list="$list" command='snmpwalk -c public -v1 "$target_ip" 1.3.6.1.4.1.77.1.2.25' file="vulns" fn_display 
    $snmp_fn_display vulns

    # enumerates running processes
    Object snmp vulns list="$list" command='snmpwalk -c public -v1 "$target_ip" 1.3.6.1.2.1.25.4.2.1.2' file="vulns" fn_display 
    $snmp_fn_display vulns

}

scan_MYSQL () {
    list=$1
    # mysql-audit.nse, mysql-brute.nse,
    # mysql-enum.nse, mysql-info.nse, mysql-query.nse, mysql-users.nse, 
    # mysql-variables.nse
    call_header "Scanning for vulns - MYSQL..."
    Object mysql vulns list="$list" command='nmap -sV -Pn --script mysql-vuln* "$target_ip" -p"$port"' file="vulns" fn_display 
    $mysql_fn_display vulns

    call_header "Dumping hashes - MYSQL..."
    Object mysql vulns list="$list" command='nmap -sV -Pn --script mysql-dump-hashes,mysql-databases "$target_ip" -p"$port"' file="vulns" fn_display 
    $mysql_fn_display vulns

    call_header "Bruteforcing - MYSQL..."
    Object mysql vulns list="$list" command='nmap --script mysql-brute --script-args userdb=$users_lst -sV -Pn "$target_ip" -p"$port"' file="vulns" fn_display 
    $mysql_fn_display vulns

    call_header "Loging with empty password - MYSQL..."
    Object mysql vulns list="$list" command='nmap --script mysql-empty-password -sV -Pn "$target_ip" -p"$port"' file="vulns" fn_display 
    $mysql_fn_display vulns

    call_header "Banner grabbing with mysql - MYSQL..."
    Object mysql vulns list="$list" command='mysql --host="$target_ip" -u anonymous -V' file="vulns" fn_display 
    $mysql_fn_display vulns
}    

scan_LDAP () {
    list=$1
    #TODO: find and fix this
    call_header "Scanning for vulns - LDAP..."
    # ldap-brute.nse, ldap-novell-getpass.nse,ldap-rootdse.nse

    Object ldap nmap list="$list" command='nmap -Pn -sV -p"$port" --script=ldap-search "$target_ip"' file="vulns" fn_display 
    $ldap_fn_display nmap

    # scanning with crackmapexec
    call_header "Scaning with crackmapexec..."
    Object ldap crackmapexec list="$list" command='crackmapexec ldap "$target_ip"' file="vulns" fn_display 
    $ldap_fn_display crackmapexec


    #     ldapsearch -h "$p" -p 389 -x -b "dc=mywebsite,dc=com"
    #     ldapsearch -h "$p" -p 636 -x -b "dc=mywebsite,dc=com"
    #     ldapsearch -h "$p" -p 3268 -x -b "dc=mywebsite,dc=com"

}

scan_MS_SQL () {
    list=$1
    call_header "Scanning for vulns - MS-SQL..."

    # ms-sql-brute.nse
    # ms-sql-query.nse

    Object mssql vulns list="$list" command='nmap --script ms-sql-info,ms-sql-empty-password,ms-sql-xp-cmdshell,ms-sql-config,ms-sql-ntlm-info,ms-sql-tables,ms-sql-hasdbaccess,ms-sql-dac,ms-sql-dump-hashes --script-args mssql.instance-port=$port,mssql.username=sa,mssql.password=,mssql.instance-name=MSSQLSERVER "$target_ip" -p "$port"'  file="vulns" fn_display 
    $mssql_fn_display vulns


    # scanning with crackmapexec
    call_header "Scaning with crackmapexec..."
    Object mssql crackmapexec list="$list" command='crackmapexec mssql "$target_ip"' file="vulns" fn_display 
    $mssql_fn_display crackmapexec


    # TODO: fix redirection
    # while IFS="" read -r p || [ -n "$p" ]
    # do
    #     sqsh -S IP_Address:PORT -u username -p password
    #     sqsh -S "$p" -U sa
    # done < "$list"
    call_header "Atempting to login with anonymous:anonymous - MS-SQL..."
    Object ftp anonLog list="$list" command='/usr/bin/impacket-mssqlclient anonymous:anonymous@"$target_ip -port $port"' file="vulns" fn_display 
    $ftp_fn_display anonLog


    # fix sqsh -U sa -S 10.11.1.13 -p 1433 
    # sqsh -S IP_Address:PORT -u username -p password
    # Object mssql vulns list="$list" command="sqsh -U sa -S" file="vulns" fn_display 
    # $mssql_fn_display vulns

    # call_header "Bruteforcing - SSH..."
    # nmap -p1433 --script ms-sql-brute --script-args userdb "$users_lst",passdb="$pass_lst" "$list"
    # printf "\n\n"
}

scan_ORACLE_DB () {
    list=$1
    call_header "Scanning for vulns - ORACLE-DB..."
    # oracle-brute.nse, oracle-brute-stealth.nse, oracle-enum-users.nse
    # oracle-sid-brute.nse
    
    Object oracle vulns list="$list" command='nmap -sV -Pn --script oracle-tns-version,oracle-enum-users "$target_ip" -p"$port"' file="vulns" fn_display 
    $oracle_fn_display vulns
}

scan_ORACLE_WEB () {
    list=$1
    call_header "Scanning for vulns - ORACLE-WEB..."

    # oracle-brute.nse, oracle-brute-stealth.nse,
    # oracle-enum-users.nse, oracle-sid-brute.nse
    Object oracle vulns list="$list" command='nmap -sV -Pn --script oracle-tns-version,oracle-enum-users "$target_ip" -p"$port"' file="vulns" fn_display 
    $oracle_fn_display vulns
}    

scan_RDP () {
    list=$1

    # scanning with crackmapexec
    call_header "Scaning with crackmapexec..."
    Object rdp crackmapexec list="$list" command='crackmapexec winrm "$target_ip"' file="vulns" fn_display 
    $rdp_fn_display crackmapexec

    call_header "Scanning for vulns - RDP..."
    Object rdp vulns list="$list" command='nmap -sV -Pn --script rdp-vuln-ms12-020 "$target_ip" -p"$port"' file="vulns" fn_display 
    $rdp_fn_display vulns
}

scan_VNC () {
    #RDP for linux
    list=$1

    # scanning with crackmapexec
    call_header "Scaning with crackmapexec..."
    Object vnc crackmapexec list="$list" command='crackmapexec winrm "$target_ip"' file="vulns" fn_display 
    $vnc_fn_display crackmapexec

    call_header "Scanning for vulns - VNC..."
    Object vnc vulns list="$list" command='nmap -sV --script rdp-vuln-ms12-020 "$target_ip" -p"$port"' file="vulns" fn_display 
    $vnc_fn_display vulns

    call_header "Scanning for vulns - VNC..."
    Object vnc vncviewer list="$list" command='vncviewer "$target_ip":"$port"' file="vulns" fn_display 
    $vnc_fn_display vncviewer
}

scan_MSRDP () {
    # Checking the available encryption and DoS vulnerability (without causing DoS to the service) and obtains NTLM Windows info (versions).
    call_header "Scanning for vulns - MSRDP..."
    Object msrdp vulns list="$list" command='nmap -T4 --script rdp-enum-encryption,rdp-vuln-ms12-020,rdp-ntlm-info -p "$port" "$target_ip"' file="vulns" fn_display 
    $msrdp_fn_display vulns
}

scan_HTTP () {
    local list=$1
    # echo "$list"
    # out="$(echo "$list" | cut -d "/" -f4 | cut -d "." -f1 )"
    # local tee_output="tee -a $service_vulns/$out"

    # local func=$http_fn_display
    
    # call_header "Scaning for headers..."
    # Object http headers list="$list" command='curl -i "$target_ip:$port"' file="vulns" fn_display 
    # $http_fn_display headers

    call_header "Scaning with whatweb..."
    Object http whatweb list="$list" command='whatweb -v "$target_ip:$port"' file="vulns" fn_display 
    $http_fn_display whatweb

    call_header "Downloading default landing page..."
    Object http landingPage list="$list" command='curl -i -L "$target_ip:$port"' file="vulns" fn_display 
    $http_fn_display landingPage

    call_header "Scanning for Internal & External Links..."
    Object http links list="$list" command='curl -i -L "$target_ip:$port"' file="vulns" pipe="| grep 'title\|href' | sed -e 's/^[[:space:]]*//'" fn_display 
    $http_fn_display links

    call_header "Scaning for HTML..."
    Object http htmlScan list="$list" command='curl -s -L "$target_ip:$port"' file="vulns" pipe="| html2text -width '99' | uniq" fn_display 
    $http_fn_display htmlScan

    call_header "Scaning for README..."
    Object http readMe list="$list" command='curl "$target_ip:$port"/README.md' file="vulns" pipe="| grep -iE 'release'" fn_display 
    $http_fn_display readMe 

    call_header "Scaning for robots.txt..."
    Object http robotsTxt list="$list" command='curl -s http://"$target_ip:$port"/robots.txt' file="vulns" pipe="| html2text" fn_display 
    $http_fn_display robotsTxt 
    # call_loop "$list" "$tee_output" "parsero -u"

    call_header "Scaning for directories with gobuster..."
    if [ "$PROXY" != '' ]; then
        Object http directories list="$list" command='gobuster dir -k --proxy socks5://127.0.0.1:1080 -x html,bak,txt,css,cgi,php,asp,aspx,xml,conf,db,pl,cgi -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -s "200,204,301,302,307,500" -b "404,400,403" --no-progress --no-error -u https://"$target_ip:$port"' file="gobuster" fn_display 
        $http_fn_display directories 
    else
        Object http directories list="$list" command='gobuster dir -x html,bak,txt,css,cgi,php,asp,aspx,xml,conf,db,pl,cgi -w /usr/share/seclists/Discovery/Web-Content/common.txt --no-progress --no-error -u http://"$target_ip:$port"' file="gobuster" fn_display 
        $http_fn_display directories 
    fi

    call_header "Scaning for vulns with nikto..."
    Object http nikto list="$list" command='timeout 260s nikto -host "$target_ip:$port"' file="nikto" fn_display 
    $http_fn_display nikto 
    
    # if grep -q shellshock $service_vulns/*/http.nikto; then
    #     echo $service_vulns/*/http.nikto
    #     echo "found vulns: SHELLSHOCK"
    # fi

    call_header "CGI Brute Force with gobuster..."
    Object http cgiBrute list="$list" command="gobuster dir -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt --no-progress --no-error -u $target_ip" file="cgi.list.tmp" url="/" pipe="| grep 'Status: 200'| cut -d ' ' -f1 |grep  -iE 'cgi'| sed 's/\//$target_ip\//'| tr -d '\011\013\014\015'" fn_display 
    $http_fn_display cgiBrute

    # call_loop "$list" "gobuster dir -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt --no-progress --no-error -u" "cgi.list" "/" "| grep 'Status: 200'| cut -d ' ' -f1 |grep  -iE 'cgi'| sed 's/\//$target_ip\//'| tr -d '\011\013\014\015'"
    # while IFS="" read -r p || [ -n "$p" ]
    # do
    # gobuster dir -w /usr/share/seclists/Discovery/Web-Content/CGIs.txt --no-progress --no-error -u "$p" | grep 'Status: 200'| cut -d ' ' -f1 |grep  -iE 'cgi'| sed "s/\//$p\//"| tr -d '\011\013\014\015'|& tee "$service_vulns/$out.cgi.list.tmp"
    # done < "$list"
    # printf "\n\n"

    grep  -iE 'cgi' "$service_vulns/$out.cgi.list.tmp" |tr -d '\011\013\014\015' >"$service_vulns/$out.cgi.list"

    call_header "Gathering info from CGIs..."
    call_loop "$service_vulns/$out.cgi.list" "$tee_output.cgi.html_text" "curl -i -s" "" "html2text" 

    # count=0
    # while IFS="" read -r p || [ -n "$p" ]
    # do
    #     if [ "$p" != "" ]; then
    #     local command="curl -i "$p" -s | html2text"
    #     ((count+=1))
    #     sleep .2
    #     call_header2 "$command" |& tee $service_vulns/$out.cgi.html_text_$count
    #     eval "$command" |& tee -a $service_vulns/$out.cgi.html_text_$count
    #     printf "\n\n"
    # fi
    # done < "$service_vulns/$out.cgi.list"
    # printf "\n\n"

   # nmap 10.11.1.71 -p 80 --script http-shellshock --script-args uri=/cgi-bin/test.cgi --script-args uri=/cgi-bin/admin.cgi

    # nikto -host 10.11.1.71     

    # call_header "Scanning for vulns - HTTP/HTTPS..."
    # # Segmentation fault 
    # nmap -sV -sC -vv -p80,8080,443,8443 --script nmap-vulners/ -iL "$list"
    # # nmap -sV -sC -vv -p80 --script vulscan/vulscan --script-args vulscanoutput='{id}\t{link}' -iL "$list"
    # printf "\n\n"

    # call_header "Enumerating directories - HTTP/HTTPS..."
    # similar in format to the Nikto Web application scanner. This script, however, takes it one step further by building in advanced pattern matching as well as having the ability to identify specific versions of Web applications.
    # nmap -sV -sC -vv -p80,8080,443,8443 --script http-enum -iL "$list"
    # printf "\n\n"

    # call_header "Enumerating configuration copies - HTTP/HTTPS..."
    # # The http-config-backup script sends many queries to the web server, trying to get a copy of the configuration of popular CMS left behind by the user or text editor. 
    # # Segmentation fault 
    # nmap -sV -sC -vv -p80,8080,443,8443 --script http-config-backup -iL "$list"
    # printf "\n\n"

    # call_header "Enumerating email addresses, IPs and etc - HTTP/HTTPS..."
    # # The http-grep script searches the given page for useful information. By default, it returns the e-mail addresses and IP addresses found on all subpages discovered by the script. We can give the script in the http-grep.url argument subpage that we want to search, and using the argument, http-grep.builtins, we will extend the scope of the search to email addresses, IP addresses, phone numbers, mastercard, visa, discover, amex, and ssn cards. If we want to add a word or regular expression to be searched, we pass it to the argument, http-grep.match. By default, set to 3, the search depth can be changed using the http-grep.maxdepth argument.
    # # Segmentation fault 
    # nmap -sV -sC -vv -p80,8080,443,8443 --script http-grep -iL "$list"
    # printf "\n\n"

    # call_header "Bruteforcing proxy servers - HTTP/HTTPS..."
    # # Performs brute force password guessing against HTTP proxy servers.
    # # Segmentation fault 
    # nmap -sV -sC -vv -p80,8080,443,8443 --script http-proxy-brute -iL "$list"
    # printf "\n\n"

    # call_header "Bruteforcing auth - HTTP/HTTPS..."
    # # Performs brute force password auditing against http basic, digest and ntlm authentication.
    # # Segmentation fault 
    # nmap -sV -sC -vv -p80,8080,443,8443 -script http-brute -iL "$list"
    # printf "\n\n"

    # call_header "Enumerating RFI - HTTP/HTTPS..."
    # # Crawls webservers in search of RFI (remote file inclusion) vulnerabilities. It tests every form field it finds and every parameter of a URL containing a query.
    # # Segmentation fault 
    # nmap -sV -sC -vv -p80,8080,443,8443 --script http-rfi-spider -iL "$list"
    # printf "\n\n"

    # call_header "Enumerating default accounts - HTTP/HTTPS..."
    # # Tests for access with default credentials used by a variety of web applications and devices.
    # # Segmentation fault 
    # nmap -sV -sC -vv -p80,8080,443,8443 --script http-default-accounts -iL "$list"
    # printf "\n\n"

    # # TODO: add php shell file
    # call_header "Performing remote file inclusion - HTTP/HTTPS..."
    # # Uploads a local file to a remote web server using the HTTP PUT method. You must specify the filename and URL path with NSE arguments.
    # # Segmentation fault 
    # nmap -sV -sC -vv -p80,8080,443,8443 --script http-put --script-args http-put.url='/uploads/rootme.php',http-put.file='192.168.119.145/psexec.py' -iL "$list"
    # printf "\n\n"

    # call_header "Enumerating DNS hostnames - HTTP/HTTPS..."
    # # Attempts to enumerate DNS hostnames by brute force guessing of common subdomains.
    # # The dns-brute script tries to find as many subdomains as the host is being tested using the most frequently used subdomain names.
    # # Segmentation fault 
    # nmap -p80,8080,443,8443 --script dns-brute -iL "$list"

    # nmap -p80,8080,443,8443 --script dns-brute --script-args dns-brute.domain="$list",dns-brute.threads=6,dns-brute.hostlist="$host_lst",newtargets -sS -iL "$list"

    # wordpress bruteforcing, uncomment this if you think the target website is on WP
    # call_header "Bruteforcing WP - HTTP/HTTPS..."
    # nmap -sV --script http-wordpress-brute --script-args userdb="$users_lst",passdb="$pass_lst",http-wordpress-brute.hostname="$list", http-wordpress-brute.threads=3,brute.firstonly=true "$list"
    printf "\n\n"
}

perform_vuln_scan () {
    for filename in "$service_list"/*; do
        [ -e "$filename" ] || continue
        [[ $filename == *http* ]] && scan_HTTP "$filename"

        [[ $filename == *ftp* ]] &&  scan_FTP "$filename"

        [[ $filename == *ms-sql* ]] && scan_MS_SQL "$filename"

        [[ $filename == *smb* ]] && scan_SMB "$filename"

        [[ $filename == *netbios* ]] && scan_SMB "$filename"

        [[ $filename == *microsoft-ds* ]] && scan_SMB "$filename"

        [[ $filename == *ms-wbt-server* ]] &&  scan_MSRDP "$filename"

        [[ $filename == *msrpc* ]] && scan_MSRPC "$filename"

        [[ $filename == *vnc* ]] && scan_VNC "$filename"

        [[ $filename == *ssh* ]] && scan_SSH "$filename"

        [[ $filename == *telnet* ]] && scan_TELNET "$filename"

        [[ $filename == *smtp* ]] && scan_SMTP "$filename"
        
        [[ $filename == *kerberos* ]] && scan_KERBEROS "$filename"
        
        [[ $filename == *pop3* ]] && scan_POP3 "$filename"
        
        [[ $filename == *nfs_acl* ]] && scan_NFS "$filename"
        
        [[ $filename == *rpcbind* ]] && scan_NFS "$filename"

        [[ $filename == *nntp* ]] && scan_NNTP "$filename"
        
        [[ $filename == *imap* ]] && scan_IMAP "$filename"

        [[ $filename == *snmp* ]] && scan_SNMP "$filename"

        [[ $filename == *mysql* ]] && scan_MYSQL "$filename"

        [[ $filename == *ldap* ]] && scan_LDAP "$filename"

        [[ $filename == *oracle-db* ]] && scan_ORACLE_DB "$filename"

        [[ $filename == *oracle-web.* ]] && scan_ORACLE_WEB "$filename"

        [[ $filename == *microsoft-rdp.* ]] && scan_RDP "$filename"
    done
}

perform_extract () {
    echo "perform_extract"
    extract_data "$1"

}

perform_network_scan () {
    hosts="$1.1-254"
    ping_all_hosts "$hosts"
    ping_all_hosts_without_ICMP "$hosts"
    perform_full_sweep_scan
    extract_data
}

perform_network_scan_single_host () {
    host="$1"
    scan_top_10_ports "$host"
    perform_full_sweep_scan 
    extract_data
}


usage()
{
echo "Usage:"
    echo "    sudo teapot <target> <options>"
    echo "    -h help"   
    echo "    -t target"
    echo "    -n network scan"
    echo "    -v vulns scan, must be performed after network scan"
    echo "    -P ports"
    echo "    -x extract data and perfom vulns scan"
    echo "    -F xml file to extract data from"
    echo "    -p proxychains"

    
echo "Example:"
    echo "    sudo teapot -t 10.11.1 -f                               Perform full scan on 10.11.1 subnet."
    echo "    sudo teapot -t 10.11.1.50 -f                            Perform full scan on a single enpoint 10.11.1.50"
    echo "    sudo teapot -t 10.11.1.50 -f -p                         Perform full scan on a 10.11.1.50 over proxychains4"      
    echo "    sudo teapot -t 10.11.1.50 -n -p -P 80,21                Perform network scan with proxychains on ports 21,80."
    echo "    sudo teapot -t 10.11.1.50 -x -F '~/target/full_scan'    Extract data and perform vulns scan."
exit 2
}

set_variable()
{
  local varname=$1
  shift
  if [ -z "${!varname}" ]; then
    eval "$varname=\"$@\""
  else
    echo "Error: $varname already set"
    usage
  fi
}


# read the option and store in the variable, $option
while getopts 't:P:F:fxnvp?h' option;
do
case ${option} in
    t ) set_variable TARGET "$OPTARG";;
    P ) set_variable PORTS "$OPTARG";;
    f ) set_variable ACTION FULL;;
    n ) set_variable ACTION NETWORK;;
    v ) set_variable ACTION VULNS;;
    x ) set_variable ACTION EXTRACT;;
    F ) set_variable FILE "$OPTARG";;
    p ) set_variable PROXY proxychains;;
    h|?) usage ;; esac

done

[ -z "$ACTION" ] && usage
[ -z "$TARGET" ] && usage

if [ -n "$TARGET" ]; then
    if [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        case $ACTION in
        FULL) perform_network_scan "$TARGET" && perform_vuln_scan  ;;
        NETWORK) perform_network_scan "$TARGET" ;;
        VULNS) perform_vuln_scan ;;
        esac
    elif [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        case $ACTION in
        FULL) perform_network_scan_single_host "$TARGET" && perform_vuln_scan  ;;
        NETWORK) perform_network_scan_single_host "$TARGET" ;;
        VULNS) perform_vuln_scan ;;
        esac
        if [[ -n "$FILE" ]]; then
            case $ACTION in
            EXTRACT) perform_extract "$FILE" && perform_vuln_scan;;
            esac
        fi
    fi
fi
