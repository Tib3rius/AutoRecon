# AutoReconR

AutoReconR attempts to automate parts of the network reconnaissance and service enumeration phase. Respective findings are described and summarized in an automatically generated report. As such, AutoReconR may facilitate identifying potential weaknesses in target systems more quickly and finding an entry point. 

The tool is intended to be running in the background, while the tester can focus on other tasks in parallel. For instance, in laboratory environments as offered by Offensive Security or during security exams like OSCP, the tester may start writing exploits while AutoReconR scans the remaining targets and performs automatic service enumeration. The tool is highly customizable and supports different scanning profiles in order to efficiently balance program runtime with the amount of extracted information. It should be noted though that the scanning approach is generally deep and aims at examining a system in great detail. A typical program run may take between 20 and 60 minutes, depending on the discovered system services and corresponding programs that should be subsequently executed. Applications such as enum4linux, gobuster, or nikto are able to retrieve extensive information about a target but also increase the required total scanning time. It is also noteworthy that AutoReconR **does not perform any automatic exploitation**, although respective programs can be easily integrated and triggered with the help of custom configuration files that will be automatically included at startup. 

## Origin and Features

AutoReconR is forked from [AutoRecon](https://github.com/Tib3rius/AutoRecon) by Tib3rius. The tool was extended with a number of additional features, including

* the possibility to read a list of targets from a file,
* define scanning and service enumeration profiles in custom configuration files,
* automatically store scanning results in a folder structure categorized by system service,
* trigger additional actions based on identified services and service patterns,
* balance program runtime and scanning depth with the help of complexity levels, and
* summarize findings in a corresponding PDF report.

## Requirements

* Python 3
* enscript (to be replaced later)
* colorama
* toml

Once Python 3 and enscript are installed, pip3 can be used to install the other requirements:

```bash
$ pip3 install -r requirements.txt
```

In addition it is advised downloading word lists for password brute forcing and web crawling from the SecLists project (https://github.com/danielmiessler/SecLists).

On Kali Linux, these files are stored in the /usr/share/seclists/ directory or can be installed by running:

```bash
$ sudo apt install seclists
```


