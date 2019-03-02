# AutoRecon

AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services. It is intended as a time-saving tool for use in CTFs and other penetration testing environments (e.g. OSCP). It may also be useful in real-world engagements.

The tool works by firstly performing port scans / service detection scans. From those initial results, the tool will launch further enumeration scans of those services using a number of different tools. For example, if HTTP is found, nikto will be launched (as well as many others).

Everything in the tool is highly configurable. The default configuration performs **no automated exploitation** to keep the tool in line with OSCP exam rules. If you wish to add automatic exploit tools to the configuration, you do so at your own risk. The author will not be held responsible for negative actions that result from the mis-use of this tool.

## Origin

AutoRecon was inspired by three tools which the author used during the OSCP labs: [Reconnoitre](https://github.com/codingo/Reconnoitre), [ReconScan](https://github.com/RoliSoft/ReconScan), and [bscan](https://github.com/welchbj/bscan). While all three tools were useful, none of the three alone had the functionality desired. AutoRecon combines the best features of the aforementioned tools while also implementing many new features to help testers with enumeration of multiple targets.

## Features

* Supports multiple targets in the form of IP addresses, IP ranges (CIDR notation), and resolvable hostnames.
* Can scan targets concurrently, utilizing multiple processors.
* Customizable port scanning profiles for flexibility in your initial scans.
* Customizable service enumeration commands and suggested manual follow-up commands.
* An intuitive directory structure for results gathering.
* Full logging of commands that were run.

## Requirements

* Python 3
* colorama
* toml

Once Python 3 is installed, pip3 can be used to install the other requirements:

```bash
$ pip3 install -r requirements.txt
```

Several commands used in AutoRecon reference the SecLists project, in the directory /usr/share/seclists/. You can either manually download the SecLists project to this directory (https://github.com/danielmiessler/SecLists), or if you are using Kali Linux (**highly recommended**) you can run the following:

```bash
$ sudo apt install seclists
```

AutoRecon will still run if you do not install SecLists, though several commands may fail, and some manual commands may not run either.

## Usage

AutoRecon uses Python 3 specific functionality and does not support Python 2.

```
usage: autorecon.py [-h] [-ct <number>] [-cs <number>] [--profile PROFILE]
                    [-v] [-o OUTPUT] [--disable-sanity-checks]
                    targets [targets ...]

Network reconnaissance tool to port scan and automatically enumerate services
found on multiple targets.

positional arguments:
  targets               IP addresses (e.g. 10.0.0.1), CIDR notation (e.g.
                        10.0.0.1/24), or resolvable hostnames (e.g. foo.bar)
                        to scan.

optional arguments:
  -h, --help            show this help message and exit
  -ct <number>, --concurrent-targets <number>
                        The maximum number of target hosts to scan
                        concurrently. Default: 5
  -cs <number>, --concurrent-scans <number>
                        The maximum number of scans to perform per target
                        host. Default: 10
  --profile PROFILE     The port scanning profile to use (defined in port-
                        scan-profiles.toml).
  -v, --verbose         enable verbose output, repeat for more verbosity
  -o OUTPUT, --output OUTPUT
                        output directory for the results
  --disable-sanity-checks
                        Disable sanity checks that would otherwise prevent the
                        scans from running.
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
python3 autorecon.py -ct 2 -cs 2 -v -o outputdir 192.168.1.100 192.168.1.1/30 localhost
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

In this example, the -ct option limits the number of concurrent targets to 2, and the -cs option limits the number of concurrent scans per target to 2. The -v option makes the output verbose, showing the output of every scan being run. The -o option sets a custom output directory for scan results to be saved.

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
    └── _manual_commands.txt
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

### Port Scan profiles

The port-scan-profiles.toml file is where you can define the initial port scans / service detection commands. The configuration file uses the TOML format, which is explained here: https://github.com/toml-lang/toml

Here is an example profile called "quick":

```toml
[quick]

    [quick.nmap-quick]

        [quick.nmap-quick.service-detection]
        command = 'nmap -vv --reason -Pn -sV --version-all -oN "{scandir}/_quick_tcp_nmap.txt" -oX "{scandir}/_quick_tcp_nmap.xml" {address}'
        pattern = '^(?P<port>\d+)\/(?P<protocol>(tcp|udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(.*)$'
```

Note that indentation is optional, it is used here purely for aesthetics. The "quick" profile defines a scan called "nmap-quick". This scan has a service-detection command which uses nmap to scan the top 1000 TCP ports. The command uses two references: {scandir} is the location of the scans directory for the target, and {address} is the address of the target.

A regex pattern is defined which matches three named groups (port, protocol, and service) in the output. Every service-detection command must have a corresponding pattern that matches all three of those groups. AutoRecon will attempt to do some checks and refuse to scan if any of these groups are missing.

Here is a more complicated example:

```toml
[udp]

    [udp.udp-top-20]

        [udp.udp-top-20.port-scan]
        command = 'unicornscan -mU -p 631,161,137,123,138,1434,445,135,67,53,139,500,68,520,1900,4500,514,49152,162,69 {address} 2>&1 | tee "{scandir}/_top_20_udp_unicornscan.txt"'
        pattern = '^UDP open\s*[\w-]+\[\s*(?P<port>\d+)\].*$'

        [udp.udp-top-20.service-detection]
        command = 'nmap -vv --reason -Pn -sU -A -p {ports} --version-all -oN "{scandir}/_top_20_udp_nmap.txt" -oX "{scandir}/_top_20_udp_nmap.xml" {address}'
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

```
[ftp]

service-names = [
    '^ftp',
    '^ftp\-data'
]

    [ftp.scans]

        [ftp.scans.nmap-ftp]
        command = 'nmap -vv --reason -Pn -sV {nmap_extra} -p {port} --script="(ftp* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" -oN "{scandir}/{protocol}_{port}_ftp_nmap.txt" -oX "{scandir}/{protocol}_{port}_ftp_nmap.xml" {address}'

    [ftp.manual]

        [ftp.manual.bruteforce]
        description = 'Bruteforce logins:'
        commands = [
            'hydra -L "{username_wordlist}" -P "{password_wordlist}" -e nsr -s {port} -o "{scandir}/{protocol}_{port}_ftp_hydra.txt" ftp://{address}',
            'medusa -U "{username_wordlist}" -P "{password_wordlist}" -e ns -n {port} -O "{scandir}/{protocol}_{port}_ftp_medusa.txt" -M ftp -h {address}'
        ]
```

Note that indentation is optional, it is used here purely for aesthetics. The service "ftp" is defined here. The service-names array contains regex strings which should match the service name from the service-detection scans. Regex is used to be as flexible as possible. The service-names array works on a whitelist basis; as long as one of the regex strings matches, the service will get scanned.

An optional ignore-service-names array can also be defined, if you want to blacklist certain regex strings from matching.

The ftp.scans section defines a single scan, named nmap-ftp. This scan defines a command which runs nmap with several ftp-related scripts. Several references are used here: {nmap_extra} will be blank unless the port is UDP, at which point it will be set to -sU, {port} is the port that the service is running on, {scandir} is the location of the scans directory for the target, {protocol} is the protocol being used (either tcp or udp), and {address} is the address of the target.

The ftp.manual section defines a group of manual commands called "bruteforce". This group contains a description for the user, and a commands array which contains the commands that a user can run. Two new references are defined here: {username_wordlist} and {password_wordlist} which are configured at the very top of the service-scans.toml file, and default to a username and password wordlist provided by SecLists.

Here is a more complicated configuration:

```
[smb]

service-names = [
    '^smb',
    '^microsoft\-ds',
    '^netbios'
]

    [smb.scans]

        [smb.scans.nmap-smb]
        command = 'nmap -vv --reason -Pn -sV {nmap_extra} -p {port} --script="(nbstat or smb* or ssl*) and not (brute or broadcast or dos or external or fuzzer)" --script-args=unsafe=1 -oN "{scandir}/{protocol}_{port}_smb_nmap.txt" -oX "{scandir}/{protocol}_{port}_smb_nmap.xml" {address}'

        [smb.scans.enum4linux]
        command = 'enum4linux -a -M -l -d {address} | tee "{scandir}/enum4linux.txt"'
        run_once = true
        ports.tcp = [139, 389, 445]
        ports.udp = [137]

        [smb.scans.nbtscan]
        command = 'nbtscan -rvh {address} | tee "{scandir}/nbtscan.txt"'
        run_once = true
        ports.udp = [137]

        [smb.scans.smbclient]
        command = 'smbclient -L\\ -N -I {address} | tee "{scandir}/smbclient.txt"'
        run_once = true
        ports.tcp = [139, 445]
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
>\- b0ats
