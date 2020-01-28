[![Packaging status](https://repology.org/badge/vertical-allrepos/autorecon.svg)](https://repology.org/project/autorecon/versions)

> It's like bowling with bumpers. - [@ippsec](https://twitter.com/ippsec)

# AutoRecon

AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services. It is intended as a time-saving tool for use in CTFs and other penetration testing environments (e.g. OSCP). It may also be useful in real-world engagements.

The tool works by firstly performing port scans / service detection scans. From those initial results, the tool will launch further enumeration scans of those services using a number of different tools. For example, if HTTP is found, nikto will be launched (as well as many others).

Everything in the tool is highly configurable. The default configuration performs **no automated exploitation** to keep the tool in line with OSCP exam rules. If you wish to add automatic exploit tools to the configuration, you do so at your own risk. The author will not be held responsible for negative actions that result from the mis-use of this tool.

## Origin

AutoRecon was inspired by three tools which the author used during the OSCP labs: [Reconnoitre](https://github.com/codingo/Reconnoitre), [ReconScan](https://github.com/RoliSoft/ReconScan), and [bscan](https://github.com/welchbj/bscan). While all three tools were useful, none of the three alone had the functionality desired. AutoRecon combines the best features of the aforementioned tools while also implementing many new features to help testers with enumeration of multiple targets.

## Features

* Supports multiple targets in the form of IP addresses, IP ranges (CIDR notation), and resolvable hostnames.
* Can scan targets concurrently, utilizing multiple processors if they are available.
* Customizable port scanning profiles for flexibility in your initial scans.
* Customizable service enumeration commands and suggested manual follow-up commands.
* An intuitive directory structure for results gathering.
* Full logging of commands that were run, along with errors if they fail.
* Global and per-scan pattern matching so you can highlight/extract important information from the noise.

## Requirements

* Python 3
* colorama
* toml

Once Python 3 is installed, pip3 can be used to install the other requirements:

```bash
$ pip3 install -r requirements.txt
```

Several people have indicated that installing pip3 via apt on the OSCP Kali version makes the host unstable. In these cases, pip3 can be installed by running the following commands:

```bash
$ curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
$ python3 get-pip.py
```

The "pip3" command should now be usable.

Several commands used in AutoRecon reference the SecLists project, in the directory /usr/share/seclists/. You can either manually download the SecLists project to this directory (https://github.com/danielmiessler/SecLists), or if you are using Kali Linux (**highly recommended**) you can run the following:

```bash
$ sudo apt install seclists
```

AutoRecon will still run if you do not install SecLists, though several commands may fail, and some manual commands may not run either.

Additionally the following commands may need to be installed, depending on your OS:

```
curl
enum4linux
gobuster
nbtscan
nikto
nmap
onesixtyone
oscanner
smbclient
smbmap
smtp-user-enum
snmpwalk
sslscan
svwar
tnscmd10g
whatweb
wkhtmltoimage
```

## Usage

AutoRecon uses Python 3 specific functionality and does not support Python 2.

```
usage: autorecon.py [-h] [-t TARGET_FILE] [-ct <number>] [-cs <number>]
                    [--profile PROFILE_NAME] [-o OUTPUT_DIR] [--single-target]
                    [--only-scans-dir] [--heartbeat HEARTBEAT]
                    [--nmap NMAP | --nmap-append NMAP_APPEND] [-v]
                    [--disable-sanity-checks]
                    [targets [targets ...]]

Network reconnaissance tool to port scan and automatically enumerate services
found on multiple targets.

positional arguments:
  targets               IP addresses (e.g. 10.0.0.1), CIDR notation (e.g.
                        10.0.0.1/24), or resolvable hostnames (e.g. foo.bar)
                        to scan.

optional arguments:
  -h, --help            show this help message and exit
  -t TARGET_FILE, --targets TARGET_FILE
                        Read targets from file.
  -ct <number>, --concurrent-targets <number>
                        The maximum number of target hosts to scan
                        concurrently. Default: 5
  -cs <number>, --concurrent-scans <number>
                        The maximum number of scans to perform per target
                        host. Default: 10
  --profile PROFILE_NAME
                        The port scanning profile to use (defined in port-
                        scan-profiles.toml). Default: default
  -o OUTPUT_DIR, --output OUTPUT_DIR
                        The output directory for results. Default: results
  --single-target       Only scan a single target. A directory named after the
                        target will not be created. Instead, the directory
                        structure will be created within the output directory.
                        Default: false
  --only-scans-dir      Only create the "scans" directory for results. Other
                        directories (e.g. exploit, loot, report) will not be
                        created. Default: false
  --heartbeat HEARTBEAT
                        Specifies the heartbeat interval (in seconds) for task
                        status messages. Default: 60
  --nmap NMAP           Override the {nmap_extra} variable in scans. Default:
                        -vv --reason -Pn
  --nmap-append NMAP_APPEND
                        Append to the default {nmap_extra} variable in scans.
  -v, --verbose         Enable verbose output. Repeat for more verbosity.
  --disable-sanity-checks
                        Disable sanity checks that would otherwise prevent the
                        scans from running. Default: false
```

### Examples

**Scanning a single target:**

```
python3 autorecon.py 127.0.0.1
[*] Scanning target 127.0.0.1
[*] Running service detection nmap-full-tcp on 127.0.0.1
[*] Running service detection nmap-top-20-udp on 127.0.0.1
[*] Running service detection nmap-quick on 127.0.0.1
[*] Service detection nmap-quick on 127.0.0.1 finished successfully
[*] [127.0.0.1] ssh found on tcp/22
[*] [127.0.0.1] http found on tcp/80
[*] [127.0.0.1] rpcbind found on tcp/111
[*] [127.0.0.1] postgresql found on tcp/5432
[*] Running task tcp/22/nmap-ssh on 127.0.0.1
[*] Running task tcp/80/nmap-http on 127.0.0.1
[*] Running task tcp/80/curl-index on 127.0.0.1
[*] Running task tcp/80/curl-robots on 127.0.0.1
[*] Running task tcp/80/whatweb on 127.0.0.1
[*] Running task tcp/80/nikto on 127.0.0.1
[*] Running task tcp/111/nmap-nfs on 127.0.0.1
[*] Task tcp/80/curl-index on 127.0.0.1 finished successfully
[*] Task tcp/80/curl-robots on 127.0.0.1 finished successfully
[*] Task tcp/22/nmap-ssh on 127.0.0.1 finished successfully
[*] Task tcp/80/whatweb on 127.0.0.1 finished successfully
[*] Task tcp/111/nmap-nfs on 127.0.0.1 finished successfully
[*] Task tcp/80/nmap-http on 127.0.0.1 finished successfully
[*] Task tcp/80/nikto on 127.0.0.1 finished successfully
[*] Service detection nmap-top-20-udp on 127.0.0.1 finished successfully
[*] Service detection nmap-full-tcp on 127.0.0.1 finished successfully
[*] [127.0.0.1] http found on tcp/5984
[*] [127.0.0.1] rtsp found on tcp/5985
[*] Running task tcp/5984/nmap-http on 127.0.0.1
[*] Running task tcp/5984/curl-index on 127.0.0.1
[*] Running task tcp/5984/curl-robots on 127.0.0.1
[*] Running task tcp/5984/whatweb on 127.0.0.1
[*] Running task tcp/5984/nikto on 127.0.0.1
[*] Task tcp/5984/curl-index on 127.0.0.1 finished successfully
[*] Task tcp/5984/curl-robots on 127.0.0.1 finished successfully
[*] Task tcp/5984/whatweb on 127.0.0.1 finished successfully
[*] Task tcp/5984/nikto on 127.0.0.1 finished successfully
[*] Task tcp/5984/nmap-http on 127.0.0.1 finished successfully
[*] Finished scanning target 127.0.0.1
```

The default port scan profile first performs a full TCP port scan, a top 20 UDP port scan, and a top 1000 TCP port scan. You may ask why AutoRecon scans the top 1000 TCP ports at the same time as a full TCP port scan (which also scans those ports). The reason is simple: most open ports will generally be in the top 1000, and we want to start enumerating services quickly, rather than wait for Nmap to scan every single port. As you can see, all the service enumeration scans actually finish before the full TCP port scan is done. While there is a slight duplication of efforts, it pays off by getting actual enumeration results back to the tester quicker.

Note that the actual command line output will be colorized if your terminal supports it.

**Scanning multiple targets**

```
python3 autorecon.py 192.168.1.100 192.168.1.1/30 localhost
[*] Scanning target 192.168.1.100
[*] Scanning target 192.168.1.1
[*] Scanning target 192.168.1.2
[*] Scanning target localhost
[*] Running service detection nmap-quick on 192.168.1.100
[*] Running service detection nmap-quick on localhost
[*] Running service detection nmap-top-20-udp on 192.168.1.100
[*] Running service detection nmap-quick on 192.168.1.1
[*] Running service detection nmap-quick on 192.168.1.2
[*] Running service detection nmap-top-20-udp on 192.168.1.1
[*] Running service detection nmap-full-tcp on 192.168.1.100
[*] Running service detection nmap-top-20-udp on localhost
[*] Running service detection nmap-top-20-udp on 192.168.1.2
[*] Running service detection nmap-full-tcp on localhost
[*] Running service detection nmap-full-tcp on 192.168.1.1
[*] Running service detection nmap-full-tcp on 192.168.1.2
...
```

AutoRecon supports multiple targets per scan, and will expand IP ranges provided in CIDR notation. By default, only 5 targets will be scanned at a time, with 10 scans per target.

**Scanning multiple targets with advanced options**

```
python3 autorecon.py -ct 2 -cs 2 -vv -o outputdir 192.168.1.100 192.168.1.1/30 localhost
[*] Scanning target 192.168.1.100
[*] Scanning target 192.168.1.1
[*] Running service detection nmap-quick on 192.168.1.100 with nmap -vv --reason -Pn -sV -sC --version-all -oN "/root/outputdir/192.168.1.100/scans/_quick_tcp_nmap.txt" -oX "/root/outputdir/192.168.1.100/scans/_quick_tcp_nmap.xml" 192.168.1.100
[*] Running service detection nmap-quick on 192.168.1.1 with nmap -vv --reason -Pn -sV -sC --version-all -oN "/root/outputdir/192.168.1.1/scans/_quick_tcp_nmap.txt" -oX "/root/outputdir/192.168.1.1/scans/_quick_tcp_nmap.xml" 192.168.1.1
[*] Running service detection nmap-top-20-udp on 192.168.1.100 with nmap -vv --reason -Pn -sU -A --top-ports=20 --version-all -oN "/root/outputdir/192.168.1.100/scans/_top_20_udp_nmap.txt" -oX "/root/outputdir/192.168.1.100/scans/_top_20_udp_nmap.xml" 192.168.1.100
[*] Running service detection nmap-top-20-udp on 192.168.1.1 with nmap -vv --reason -Pn -sU -A --top-ports=20 --version-all -oN "/root/outputdir/192.168.1.1/scans/_top_20_udp_nmap.txt" -oX "/root/outputdir/192.168.1.1/scans/_top_20_udp_nmap.xml" 192.168.1.1
[-] [192.168.1.1 nmap-quick] Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-01 17:25 EST
[-] [192.168.1.100 nmap-quick] Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-01 17:25 EST
[-] [192.168.1.100 nmap-top-20-udp] Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-01 17:25 EST
[-] [192.168.1.1 nmap-top-20-udp] Starting Nmap 7.70 ( https://nmap.org ) at 2019-03-01 17:25 EST
[-] [192.168.1.1 nmap-quick] NSE: Loaded 148 scripts for scanning.
[-] [192.168.1.1 nmap-quick] NSE: Script Pre-scanning.
[-] [192.168.1.1 nmap-quick] NSE: Starting runlevel 1 (of 2) scan.
[-] [192.168.1.1 nmap-quick] Initiating NSE at 17:25
[-] [192.168.1.1 nmap-quick] Completed NSE at 17:25, 0.00s elapsed
[-] [192.168.1.1 nmap-quick] NSE: Starting runlevel 2 (of 2) scan.
[-] [192.168.1.1 nmap-quick] Initiating NSE at 17:25
[-] [192.168.1.1 nmap-quick] Completed NSE at 17:25, 0.00s elapsed
[-] [192.168.1.1 nmap-quick] Initiating ARP Ping Scan at 17:25
[-] [192.168.1.100 nmap-quick] NSE: Loaded 148 scripts for scanning.
[-] [192.168.1.100 nmap-quick] NSE: Script Pre-scanning.
[-] [192.168.1.100 nmap-quick] NSE: Starting runlevel 1 (of 2) scan.
[-] [192.168.1.100 nmap-quick] Initiating NSE at 17:25
[-] [192.168.1.100 nmap-quick] Completed NSE at 17:25, 0.00s elapsed
[-] [192.168.1.100 nmap-quick] NSE: Starting runlevel 2 (of 2) scan.
[-] [192.168.1.100 nmap-quick] Initiating NSE at 17:25
[-] [192.168.1.100 nmap-quick] Completed NSE at 17:25, 0.00s elapsed
[-] [192.168.1.100 nmap-quick] Initiating ARP Ping Scan at 17:25
...
```

In this example, the -ct option limits the number of concurrent targets to 2, and the -cs option limits the number of concurrent scans per target to 2. The -vv option makes the output very verbose, showing the output of every scan being run. The -o option sets a custom output directory for scan results to be saved.

### Verbosity

AutoRecon supports three levels of verbosity:

* (none) Minimal output. AutoRecon will announce when target scans start and finish, as well as which services were identified.
* (-v) Verbose output. AutoRecon will additionally specify the exact commands which are being run, as well as highlighting any patterns which are matched in command output.
* (-vv) Very verbose output. AutoRecon will output everything. Literally every line from all commands which are currently running. When scanning multiple targets concurrently, this can lead to a ridiculous amount of output. It is not advised to use -vv unless you absolutely need to see live output from commands.

### Results

By default, results will be stored in the ./results directory. A new sub directory is created for every target. The structure of this sub directory is:

```
.
├── exploit/
├── loot/
├── report/
│   ├── local.txt
│   ├── notes.txt
│   ├── proof.txt
│   └── screenshots/
└── scans/
    ├── _commands.log
    ├── _manual_commands.txt
    └── xml/
```

The exploit directory is intended to contain any exploit code you download / write for the target.

The loot directory is intended to contain any loot (e.g. hashes, interesting files) you find on the target.

The report directory contains some auto-generated files and directories that are useful for reporting:
* local.txt can be used to store the local.txt flag found on targets.
* notes.txt should contain a basic template where you can write notes for each service discovered.
* proof.txt can be used to store the proof.txt flag found on targets.
* The screenshots directory is intended to contain the screenshots you use to document the exploitation of the target.

The scans directory is where all results from scans performed by AutoRecon will go. This includes port scans / service detection scans, as well as any service enumeration scans. It also contains two other files:
* \_commands.log contains a list of every command AutoRecon ran against the target. This is useful if one of the commands fails and you want to run it again with modifications.
* \_manual_commands.txt contains any commands that are deemed "too dangerous" to run automatically, either because they are too intrusive, require modification based on human analysis, or just work better when there is a human monitoring them.

If a scan results in an error, a file called \_errors.log will also appear in the scans directory with some details to alert the user.

If output matches a defined pattern, a file called \_patterns.log will also appear in the scans directory with details about the matched output.

The scans/xml directory stores any XML output (e.g. from Nmap scans) separately from the main scan outputs, so that the scans directory itself does not get too cluttered.

### Port Scan profiles

The port-scan-profiles.toml file is where you can define the initial port scans / service detection commands. The configuration file uses the TOML format, which is explained here: https://github.com/toml-lang/toml

Here is an example profile called "quick":

```toml
[quick]

    [quick.nmap-quick]

        [quick.nmap-quick.service-detection]
        command = 'nmap {nmap_extra} -sV --version-all -oN "{scandir}/_quick_tcp_nmap.txt" -oX "{scandir}/xml/_quick_tcp_nmap.xml" {address}'
        pattern = '^(?P<port>\d+)\/(?P<protocol>(tcp|udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(.*)$'

    [quick.nmap-top-20-udp]

        [quick.nmap-top-20-udp.service-detection]
        command = 'nmap {nmap_extra} -sU -A --top-ports=20 --version-all -oN "{scandir}/_top_20_udp_nmap.txt" -oX "{scandir}/xml/_top_20_udp_nmap.xml" {address}'
        pattern = '^(?P<port>\d+)\/(?P<protocol>(tcp|udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(.*)$'
```

Note that indentation is optional, it is used here purely for aesthetics. The "quick" profile defines a scan called "nmap-quick". This scan has a service-detection command which uses nmap to scan the top 1000 TCP ports. The command uses two references: {scandir} is the location of the scans directory for the target, and {address} is the address of the target.

A regex pattern is defined which matches three named groups (port, protocol, and service) in the output. Every service-detection command must have a corresponding pattern that matches all three of those groups. AutoRecon will attempt to do some checks and refuse to scan if any of these groups are missing.

An almost identical scan called "nmap-top-20-udp" is also defined. This scans the top 20 UDP ports.

Here is a more complicated example:

```toml
[udp]

    [udp.udp-top-20]

        [udp.udp-top-20.port-scan]
        command = 'unicornscan -mU -p 631,161,137,123,138,1434,445,135,67,53,139,500,68,520,1900,4500,514,49152,162,69 {address} 2>&1 | tee "{scandir}/_top_20_udp_unicornscan.txt"'
        pattern = '^UDP open\s*[\w-]+\[\s*(?P<port>\d+)\].*$'

        [udp.udp-top-20.service-detection]
        command = 'nmap {nmap_extra} -sU -A -p {ports} --version-all -oN "{scandir}/_top_20_udp_nmap.txt" -oX "{scandir}/xml/_top_20_udp_nmap.xml" {address}'
        pattern = '^(?P<port>\d+)\/(?P<protocol>(udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(.*)$'
```

In this example, a profile called "udp" defines a scan called "udp-top-20". This scan has two commands, one is a port-scan and the other is a service-detection. When a port-scan command is defined, it will always be run first. The corresponding pattern must match a named group "port" which extracts the port number from the output.

The service-detection will be run after the port-scan command has finished, and uses a new reference: {ports}. This reference is a comma-separated string of all the ports extracted by the port-scan command. Note that the same three named groups (port, protocol, and service) are defined in the service-detection pattern.

Both the port-scan and the service-detection commands use the {scandir} and {address} references.

Note that if a port-scan command is defined without a corresponding service-detection command, AutoRecon will refuse to scan.

This more complicated example is only really useful if you want to use unicornscan's speed in conjuction with nmap's service detection abilities. If you are content with using Nmap for both port scanning and service detection, you do not need to use this setup.

### Service Scans

The service-scans.toml file is where you can define service enumeration scans and other manual commands associated with certain services.

Here is an example of a simple configuration:

```toml
[ftp]

service-names = [
    '^ftp',
    '^ftp\-data'
]

    [[ftp.scan]]
    name = 'nmap-ftp'
    command = 'nmap {nmap_extra} -sV -p {port} --script="(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_ftp_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_ftp_nmap.xml" {address}'

        [[ftp.scan.pattern]]
        description = 'Anonymous FTP Enabled!'
        pattern = 'Anonymous FTP login allowed'

    [[ftp.manual]]
    description = 'Bruteforce logins:'
    commands = [
        'hydra -L "{username_wordlist}" -P "{password_wordlist}" -e nsr -s {port} -o "{scandir}/{protocol}_{port}_ftp_hydra.txt" ftp://{address}',
        'medusa -U "{username_wordlist}" -P "{password_wordlist}" -e ns -n {port} -O "{scandir}/{protocol}_{port}_ftp_medusa.txt" -M ftp -h {address}'
    ]
```

Note that indentation is optional, it is used here purely for aesthetics. The service "ftp" is defined here. The service-names array contains regex strings which should match the service name from the service-detection scans. Regex is used to be as flexible as possible. The service-names array works on a whitelist basis; as long as one of the regex strings matches, the service will get scanned.

An optional ignore-service-names array can also be defined, if you want to blacklist certain regex strings from matching.

The ftp.scan section defines a single scan, named nmap-ftp. This scan defines a command which runs nmap with several ftp-related scripts. Several references are used here:
* {nmap_extra} by default is set to "-vv --reason -Pn" but this can be overridden or appended to using the --nmap or --nmap-append command line options respectively. If the protocol is UDP, "-sU" will also be appended.
* {port} is the port that the service is running on.
* {scandir} is the location of the scans directory for the target.
* {protocol} is the protocol being used (either tcp or udp).
* {address} is the address of the target.

A pattern is defined for the nmap-ftp scan, which matches the simple pattern "Anonymous FTP login allowed". In the event that this pattern matches output of the nmap-ftp command, the pattern description ("Anonymous FTP Enabled!") will be saved to the \_patterns.log file in the scans directory. A special reference {match} can be used in the description to reference the entire match, or the first capturing group.

The ftp.manual section defines a group of manual commands. This group contains a description for the user, and a commands array which contains the commands that a user can run. Two new references are defined here: {username_wordlist} and {password_wordlist} which are configured at the very top of the service-scans.toml file, and default to a username and password wordlist provided by SecLists.

Here is a more complicated configuration:

```toml
[smb]

service-names = [
    '^smb',
    '^microsoft\-ds',
    '^netbios'
]

    [[smb.scan]]
    name = 'nmap-smb'
    command = 'nmap {nmap_extra} -sV -p {port} --script="(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_nmap.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_nmap.xml" {address}'

    [[smb.scan]]
    name = 'enum4linux'
    command = 'enum4linux -a -M -l -d {address} 2>&1 | tee "{scandir}/enum4linux.txt"'
    run_once = true
    ports.tcp = [139, 389, 445]
    ports.udp = [137]

    [[smb.scan]]
    name = 'nbtscan'
    command = 'nbtscan -rvh {address} 2>&1 | tee "{scandir}/nbtscan.txt"'
    run_once = true
    ports.udp = [137]

    [[smb.scan]]
    name = 'smbclient'
    command = 'smbclient -L\\ -N -I {address} 2>&1 | tee "{scandir}/smbclient.txt"'
    run_once = true
    ports.tcp = [139, 445]

    [[smb.scan]]
    name = 'smbmap-share-permissions'
    command = 'smbmap -H {address} -P {port} 2>&1 | tee -a "{scandir}/smbmap-share-permissions.txt"; smbmap -u null -p "" -H {address} -P {port} 2>&1 | tee -a "{scandir}/smbmap-share-permissions.txt"'

    [[smb.scan]]
    name = 'smbmap-list-contents'
    command = 'smbmap -H {address} -P {port} -R 2>&1 | tee -a "{scandir}/smbmap-list-contents.txt"; smbmap -u null -p "" -H {address} -P {port} -R 2>&1 | tee -a "{scandir}/smbmap-list-contents.txt"'

    [[smb.scan]]
    name = 'smbmap-execute-command'
    command = 'smbmap -H {address} -P {port} -x "ipconfig /all" 2>&1 | tee -a "{scandir}/smbmap-execute-command.txt"; smbmap -u null -p "" -H {address} -P {port} -x "ipconfig /all" 2>&1 | tee -a "{scandir}/smbmap-execute-command.txt"'

    [[smb.manual]]
    description = 'Nmap scans for SMB vulnerabilities that could potentially cause a DoS if scanned (according to Nmap). Be careful:'
    commands = [
        'nmap {nmap_extra} -sV -p {port} --script="smb-vuln-ms06-025" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_ms06-025.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_ms06-025.xml" {address}',
        'nmap {nmap_extra} -sV -p {port} --script="smb-vuln-ms07-029" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_ms07-029.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_ms07-029.xml" {address}',
        'nmap {nmap_extra} -sV -p {port} --script="smb-vuln-ms08-067" --script-args="unsafe=1" -oN "{scandir}/{protocol}_{port}_smb_ms08-067.txt" -oX "{scandir}/xml/{protocol}_{port}_smb_ms08-067.xml" {address}'
    ]
```

The main difference here is that several scans have some new settings:

* The ports.tcp array defines a whitelist of TCP ports which the command can be run against. If the service is detected on a port that is not in the whitelist, the command will not be run against it.
* The ports.udp array defines a whitelist of UDP ports which the command can be run against. It operates in the same way as the ports.tcp array.

Why do these settings even exist? Well, some commands will only run against specific ports, and can't be told to run against any other ports. enum4linux for example, will only run against TCP ports 139, 389, and 445, and UDP port 137.

In fact, enum4linux will always try these ports when it is run. So if the SMB service is found on TCP ports 139 and 445, AutoRecon may attempt to run enum4linux twice for no reason. This is why the third setting exists:

* If run_once is set to true, the command will only ever run once for that target, even if the SMB service is found on multiple ports.

## Testimonials

> AutoRecon was invaluable during my OSCP exam, in that it saved me from the tedium of executing my active information gathering commands myself.  I was able to start on a target with all of the information I needed clearly laid in front of me.  I would strongly recommend this utility for anyone in the PWK labs, the OSCP exam, or other environments such as VulnHub or HTB.  It is a great tool for both people just starting down their journey into OffSec and seasoned veterans alike.  Just make sure that somewhere between those two points you take the time to learn what's going on "under the hood" and how / why it scans what it does.
>
>\- b0ats (rooted 5/5 exam hosts)

> Wow, what a great find! Before using AutoRecon, ReconScan was my goto enumeration script for targets because it automatically ran the enumeration commands after it finds open ports. The only thing missing was the automatic creation of key directories a pentester might need during an engagement (exploit, loot, report, scans). Reconnoitre did this but didn't automatically run those commands for you. I thought ReconScan that was the bee's knees until I gave AutoRecon a try. It's awesome! It combines the best features of Reconnoitre (auto directory creation) and ReconScan (automatically executing the enumeration commands). All I have to do is run it on a target or a set of targets and start going over the information it has already collected while it continues the rest of scan. The proof is in the pudding :) Passed the OSCP exam! Kudos to Tib3rius!
>
>\- werk0ut

> A friend told me about AutoRecon, so I gave it a try in the PWK labs. AutoRecon launches the common tools we all always use, whether it be nmap or nikto, and also creates a nice subfolder system based on the targets you are attacking. The strongest feature of AutoRecon is the speed; on the OSCP exam I left the tool running in the background while I started with another target, and in a matter of minutes I had all of the AutoRecon output waiting for me. AutoRecon creates a file full of commands that you should try manually, some of which may require tweaking (for example, hydra bruteforcing commands). It's good to have that extra checklist.
>
>\- tr3mb0 (rooted 4/5 exam hosts)

> Being introduced to AutoRecon was a complete game changer for me while taking the OSCP and establishing my penetration testing methodology. AutoRecon is a multi-threaded reconnaissance tool that combines and automates popular enumeration tools to do most of the hard work for you. You can't get much better than that! After running AutoRecon on my OSCP exam hosts, I was given a treasure chest full of information that helped me to start on each host and pass on my first try. The best part of the tool is that it automatically launches further enumeration scans based on the initial port scans (e.g. run enum4linux if SMB is detected). The only bad part is that I did not use this tool sooner! Thanks Tib3rius.
>
>\- rufy (rooted 4/5 exam hosts)

> AutoRecon allows a security researcher to iteratively scan hosts and identify potential attack vectors. Its true power comes in the form of performing scans in the background while the attacker is working on another host. I was able to start my scans and finish a specific host I was working on - and then return to find all relevant scans completed. I was then able to immediately begin trying to gain initial access instead of manually performing the active scanning process. I will continue to use AutoRecon in future penetration tests and CTFs, and highly recommend you do the same.
>
>\- waar (rooted 4.99/5 exam hosts)

> "If you have to do a task more than twice a day, you need to automate it." That's a piece of advice that an old boss gave to me. AutoRecon takes that lesson to heart. Whether you're sitting in the exam, or in the PWK labs, you can fire off AutoRecon and let it work its magic. I had it running during my last exam while I worked on the buffer overflow. By the time I finished, all the enum data I needed was there for me to go through. 10/10 would recommend for anyone getting into CTF, and anyone who has been at this a long time.
>
>\- whoisflynn

> I love this tool so much I wrote it.
>
>\- Tib3rius (rooted 5/5 exam hosts)

> I highly recommend anyone going for their OSCP, doing CTFs or on HTB to checkout this tool. Been using AutoRecon on HTB for a month before using it over on the PWK labs and it helped me pass my OSCP exam. If you're having a hard time getting settled with an enumeration methodology I encourage you to follow the flow and techniques this script uses. It takes out a lot of the tedious work that you're probably used to while at the same time provide well-organized subdirectories to quickly look over so you don't lose your head. The manual commands it provides are great for those specific situations that need it when you have run out of options. It's a very valuable tool, cannot recommend enough.
>
>\- d0hnuts (rooted 5/5 exam hosts)

> Autorecon is not just any other tool, it is a recon correlation framwork for engagements. This helped me fire a whole bunch of scans while I was working on other targets. This can help a lot in time management. This assisted me to own 4/5 boxes in pwk exam! Result: Passed!
>
>\- Wh0ami (rooted 4/5 exam hosts)

> The first time I heard of AutoRecon I asked whether I actually needed this, my enumeration was OK... I tried it with an open mind and straight away was a little floored on the amount of information that it would generate. Once I got used to it, and started reading the output I realized how much I was missing.  I used it for the OSCP exam, and it found things I would never have otherwise found. I firmly believe, without AutoRecon I would have failed. It's a great tool, and I'm very impressed what Tib3rius was able to craft up. Definitely something I'm already recommending to others, including you!
>
>\- othornew

> AutoRecon helped me save valuable time in my OSCP exam, allowing me to spend less time scanning systems and more time breaking into them. This software is worth its weight in gold!
>
>\- TorHackr

> The magical tool that made enumeration a piece of cake, just fire it up and watch the beauty of multi-threading spitting a ton of information that would have taken loads of commands to execute. I certainly believe that by just using AutoRecon in the OSCP exam, half of the effort would already be done. Strongly recommended!
>
>\- Arman (solved 4.5/5 exam hosts)
