> It's like bowling with bumpers. - [@ippsec](https://twitter.com/ippsec)

# Please Read Before Using

**This is a public beta of AutoRecon version 2, which is effectively a complete rewrite of version 1. As such, there are no promises about stability, and you should expect bugs. During this beta, testers are encouraged to try out the new features, especially the new plugin functionality, and report bugs when they are found. Feedback on improvements and changes is also encouraged. There is no guarantee that the current plugin system "API" will be the same when version 2 is released.**

**A wiki will be added to this repository to more fully explain the features in AutoRecon version 2.**

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

- Python 3
- `python3-pip`


### Supporting packages

Several commands used in AutoRecon reference the SecLists project, in the directory /usr/share/seclists/. You can either manually download the SecLists project to this directory (https://github.com/danielmiessler/SecLists), or if you are using Kali Linux (**highly recommended**) you can run the following:

```bash
$ sudo apt install seclists
```

AutoRecon will still run if you do not install SecLists, though several commands may fail, and some manual commands may not run either.

Additionally the following commands may need to be installed, depending on your OS:

```
curl
enum4linux
feroxbuster
impacket-scripts
nbtscan
nikto
nmap
onesixtyone
oscanner
redis-tools
smbclient
smbmap
snmpwalk
sslscan
svwar
tnscmd10g
whatweb
wkhtmltopdf
```

On Kali Linux, you can ensure these are all installed using the following command:

```bash
$ sudo apt install seclists curl enum4linux feroxbuster impacket-scripts nbtscan nikto nmap onesixtyone oscanner redis-tools smbclient smbmap snmp sslscan sipvicious tnscmd10g whatweb wkhtmltopdf
```

## Installation

Ensure you have all of the requirements installed as per the previous section.

Clone the repository and switch to the beta branch:

```bash
$ git clone --branch beta https://github.com/Tib3rius/AutoRecon
```

If you already had a copy of the repository, you can run the following from the main directory to get the beta code:

```bash
$ git pull
$ git checkout beta
```

From within the AutoRecon directory, install the dependencies:

```bash
$ python3 -m pip install -r requirements.txt
```

You will then be able to run the `autorecon.py` script:

```bash
$ python3 autorecon.py [OPTIONS] 127.0.0.1
```

See detailed usage options below.

## Usage

AutoRecon uses Python 3 specific functionality and does not support Python 2.

```
usage: autorecon.py [-t TARGET_FILE] [-m MAX_SCANS] [-mp MAX_PORT_SCANS] [-c CONFIG_FILE] [-g GLOBAL_FILE] [--tags TAGS] [--exclude-tags EXCLUDE_TAGS]                       
                    [--plugins-dir PLUGINS_DIR] [-o OUTDIR] [--single-target] [--only-scans-dir] [--create-port-dirs] [--heartbeat HEARTBEAT] [--timeout TIMEOUT]            
                    [--target-timeout TARGET_TIMEOUT] [--nmap NMAP | --nmap-append NMAP_APPEND] [--disable-sanity-checks] [--accessible] [-v] [--version]                    
                    [--curl.path VALUE] [--dirbuster.tool {feroxbuster,gobuster,dirsearch,ffuf,dirb}] [--dirbuster.wordlist VALUE] [--dirbuster.threads VALUE]               
                    [--onesixtyone.community-strings VALUE] [--global.username-wordlist VALUE] [--global.password-wordlist VALUE] [--global.domain VALUE] [-h]               
                    [targets ...]                                                                                                                                            
                                                                                                                                                                             
Network reconnaissance tool to port scan and automatically enumerate services found on multiple targets.                                                                     
                                                                                                                                                                             
positional arguments:                                                                                                                                                        
  targets               IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.                                      
                                                                                                                                                                             
  optional arguments:                                                                                                                                                 [30/2643]
    -t TARGET_FILE, --targets TARGET_FILE                                                                                                                                      
                          Read targets from file.                                                                                                                              
    -m MAX_SCANS, --max-scans MAX_SCANS                                                                                                                                        
                          The maximum number of concurrent scans to run. Default: 50                                                                                           
    -mp MAX_PORT_SCANS, --max-port-scans MAX_PORT_SCANS                                                                                                                        
                          The maximum number of concurrent port scans to run. Default: 10 (approx 20% of max-scans unless specified)                                           
    -c CONFIG_FILE, --config CONFIG_FILE                                                                                                                                       
                          Location of AutoRecon's config file. Default: /mnt/hgfs/AutoRecon/config.toml                                                                        
    -g GLOBAL_FILE, --global-file GLOBAL_FILE                                                                                                                                  
                          Location of AutoRecon's global file. Default: /mnt/hgfs/AutoRecon/global.toml                                                                        
    --tags TAGS           Tags to determine which plugins should be included. Separate tags by a plus symbol (+) to group tags together. Separate groups with a comma (,) to   
                          create multiple groups. For a plugin to be included, it must have all the tags specified in at least one group. Default: default                     
    --exclude-tags EXCLUDE_TAGS                                                                                                                                                
                          Tags to determine which plugins should be excluded. Separate tags by a plus symbol (+) to group tags together. Separate groups with a comma (,) to   
                          create multiple groups. For a plugin to be excluded, it must have all the tags specified in at least one group. Default: None
    --plugins-dir PLUGINS_DIR
                          The location of the plugins directory. Default: /mnt/hgfs/AutoRecon/plugins
    -o OUTDIR, --output OUTDIR
                          The output directory for results. Default: results
    --single-target       Only scan a single target. A directory named after the target will not be created. Instead, the directory structure will be created within the
                          output directory. Default: False
    --only-scans-dir      Only create the "scans" directory for results. Other directories (e.g. exploit, loot, report) will not be created. Default: False
    --create-port-dirs    Create directories for ports within the "scans" directory (e.g. scans/tcp80, scans/udp53) and store results in these directories. Default: False
    --heartbeat HEARTBEAT
                          Specifies the heartbeat interval (in seconds) for scan status messages. Default: 60
    --timeout TIMEOUT     Specifies the maximum amount of time in minutes that AutoRecon should run for. Default: None
    --target-timeout TARGET_TIMEOUT
                          Specifies the maximum amount of time in minutes that a target should be scanned for before abandoning it and moving on. Default: None
    --nmap NMAP           Override the {nmap_extra} variable in scans. Default: -vv --reason -Pn
    --nmap-append NMAP_APPEND
                          Append to the default {nmap_extra} variable in scans. Default: 
    --disable-sanity-checks
                          Disable sanity checks that would otherwise prevent the scans from running. Default: False
    --accessible          Attempts to make AutoRecon output more accessible to screenreaders. Default: False
	-v, --verbose         Enable verbose output. Repeat for more verbosity.
	--version             Prints the AutoRecon version and exits.
	-h, --help            Show this help message and exit.

	plugin arguments:
	  These are optional arguments for certain plugins.
	
	  --curl.path VALUE     The path on the web server to curl. Default: /
	  --dirbuster.tool {feroxbuster,gobuster,dirsearch,ffuf,dirb}
	                        The tool to use for directory busting. Default: feroxbuster
	  --dirbuster.wordlist VALUE
	                        The wordlist to use when directory busting. Specify the option multiple times to use multiple wordlists. Default:
	                        ['/usr/share/seclists/Discovery/Web-Content/common.txt']
	  --dirbuster.threads VALUE
	                        The number of threads to use when directory busting. Default: 10
	  --onesixtyone.community-strings VALUE
	                        The file containing a list of community strings to try. Default: /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings-onesixtyone.txt
	
	global plugin arguments:
	  These are optional arguments that can be used by all plugins.
	
	  --global.username-wordlist VALUE
	                        A wordlist of usernames, useful for bruteforcing. Default: /usr/share/seclists/Usernames/top-usernames-shortlist.txt
	  --global.password-wordlist VALUE
	                        A wordlist of passwords, useful for bruteforcing. Default: /usr/share/seclists/Passwords/darkweb2017-top100.txt
	  --global.domain VALUE
	                        The domain to use (if known). Used for DNS and/or Active Directory.
```

### Verbosity

AutoRecon supports three levels of verbosity:

* (none) Minimal output. AutoRecon will announce when target scans start and finish, as well as which services were identified.
* (-v) Verbose output. AutoRecon will additionally specify the exact commands which are being run, as well as highlighting any patterns which are matched in command output.
* (-vv) Very verbose output. AutoRecon will output everything. Literally every line from all commands which are currently running. When scanning multiple targets concurrently, this can lead to a ridiculous amount of output. It is not advised to use -vv unless you absolutely need to see live output from commands.

Note: You can change the verbosity of AutoRecon mid-scan by pressing the up and down arrow keys.

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

> Autorecon is not just any other tool, it is a recon correlation framweork for engagements. This helped me fire a whole bunch of scans while I was working on other targets. This can help a lot in time management. This assisted me to own 4/5 boxes in pwk exam! Result: Passed!
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
