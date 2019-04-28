#!/usr/bin/env python3
#
#    AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU General Public License, either version 3 of the License, or (at your
#    option) any later version.
#

import argparse
import asyncio
from colorama import Fore, Style
from concurrent.futures import ProcessPoolExecutor, as_completed, FIRST_COMPLETED
import ipaddress
import os
import re
import socket
import string
from datetime import datetime
import sys
import toml
import glob


__version__ = '0.1.1'

verbose = 0
nmap_default_options = '--reason -Pn'
srvname = ''

# number of possible complexity levels for scanners
max_level = 3

port_scan_profile = None
port_scan_profiles_config = None
service_scans_config = None
global_patterns = []
applications = {}

files = {
            'commands'          :   '_commands.log',
            'manual_commands'   :   '_manual_commands.log',
            'errors'            :   '_errors.log',
            'notes'             :   '_notes.txt',
            'patterns'          :   '_patterns.txt',
            'report'            :   'report.pdf',
        }

username_wordlist = '/usr/share/seclists/Usernames/top-usernames-shortlist.txt'
password_wordlist = '/usr/share/seclists/Passwords/darkweb2017-top100.txt'

rootdir = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

def e(*args, frame_index=1, **kvargs):
    frame = sys._getframe(frame_index)

    vals = {}

    vals.update(frame.f_globals)
    vals.update(frame.f_locals)
    vals.update(kvargs)

    return string.Formatter().vformat(' '.join(args), args, vals)

def cprint(*args, color=Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, **kvargs):
    frame = sys._getframe(frame_index)

    vals = {
        'bgreen':  Fore.GREEN  + Style.BRIGHT,
        'bred':    Fore.RED    + Style.BRIGHT,
        'bblue':   Fore.BLUE   + Style.BRIGHT,
        'byellow': Fore.YELLOW + Style.BRIGHT,
        'bmagenta': Fore.MAGENTA + Style.BRIGHT,

        'green':  Fore.GREEN,
        'red':    Fore.RED,
        'blue':   Fore.BLUE,
        'yellow': Fore.YELLOW,
        'magenta': Fore.MAGENTA,

        'bright': Style.BRIGHT,
        'srst':   Style.NORMAL,
        'crst':   Fore.RESET,
        'rst':    Style.NORMAL + Fore.RESET
    }

    vals.update(frame.f_globals)
    vals.update(frame.f_locals)
    vals.update(kvargs)

    clock = datetime.now().strftime('%H:%M:%S')
    clock = sep + '['  + Style.BRIGHT + Fore.YELLOW + clock + Style.NORMAL + Fore.RESET + ']'
    unfmt = ''
    if char is not None:
        unfmt += color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET + clock + sep
    unfmt += sep.join(args)

    fmted = unfmt

    for attempt in range(10):
        try:
            fmted = string.Formatter().vformat(unfmt, args, vals)
            break
        except KeyError as err:
            key = err.args[0]
            unfmt = unfmt.replace('{' + key + '}', '{{' + key + '}}')

    print(fmted, sep=sep, end=end, file=file)

def debug(*args, color=Fore.BLUE, sep=' ', end='\n', file=sys.stdout, **kvargs):
    if verbose >= 2:
        cprint(*args, color=color, char='-', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def info(*args, sep=' ', end='\n', file=sys.stdout, **kvargs):
    cprint(*args, color=Fore.GREEN, char='*', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def warn(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def error(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def fail(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
    cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)
    exit(-1)


''' Reads a configuration file, and saves the data to a dictionary

    @replace_values Dictionary with values that should be replaced in the configuration file
'''
def read_configuration_file(filename, replace_values = {}):
    data = {}
    try:
        with open(os.path.join(rootdir, 'config', filename), 'r') as f:
            data = f.read()

            for entry in replace_values:
                data = re.sub('{' +entry + '}', replace_values[entry], data)
            data = toml.loads(data)
    except (OSError, toml.decoder.TomlDecodeError) as e:
        fail('Error: The configuration file {filename} could not be read.')

    return data

def get_configuration():
    applications_config = read_configuration_file('config.toml')
    if len(applications_config) > 0 and 'applications' in applications_config:
        global applications 
        applications = applications_config['applications']
        for application in applications:
            if not os.path.isfile(applications[application]): 
                warn('Warning: The application {application} was not found on the system in the specified path.')
    else:
        warn('Warning: The section for application paths was not found in the {application_config_file} configuration file.')

    global port_scan_profiles_config 
    port_scan_profiles_config = read_configuration_file('port-scan-profiles.toml', applications)
    if len(port_scan_profiles_config) == 0:
        fail('There do not appear to be any port scan profiles configured in the {port_scan_profiles_config_file} config file.')
        return False

    global service_scans_config 
    service_scans_config = read_configuration_file('service-scans.toml', applications)

    global global_patterns 
    global_patterns = read_configuration_file('global-patterns.toml')
    if 'pattern' in global_patterns:
        global_patterns = global_patterns['pattern']
    else:
        global_patterns = []

    if 'username_wordlist' in service_scans_config:
        if isinstance(service_scans_config['username_wordlist'], str):
            username_wordlist = service_scans_config['username_wordlist']

    if 'password_wordlist' in service_scans_config:
        if isinstance(service_scans_config['password_wordlist'], str):
            password_wordlist = service_scans_config['password_wordlist']

    return True

async def read_stream(stream, target, tag='?', patterns=[], color=Fore.BLUE):
    address = target.address
    while True:
        line = await stream.readline()
        if line:
            line = str(line.rstrip(), 'utf8', 'ignore')
            debug(color + '[' + Style.BRIGHT + address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=color)

            for p in global_patterns:
                matches = re.findall(p['pattern'], line)
                if 'description' in p:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(e('{tag} - ' + p['description'] + '\n\n'))
                else:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(e('{tag} - Matched Pattern: {match}\n\n'))

            for p in patterns:
                matches = re.findall(p['pattern'], line)
                if 'description' in p:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(e('{tag} - ' + p['description'] + '\n\n'))
                else:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(e('{tag} - Matched Pattern: {match}\n\n'))
        else:
            break

async def run_cmd(semaphore, cmd, target, category='?', tag='?', patterns=[]):
    async with semaphore:
        address = target.address
        scandir = target.scandir

        if len(category) == 0: category = 'all'
        category = category.strip('/')

        info('Running task {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{cmd}{rst}.' if verbose >= 1 else '.'))

        async with target.lock:
            with open(os.path.join(scandir, files['commands']), 'a') as file:
                file.writelines(e('{category} - {cmd}\n\n'))
        
        # skip extended service scanning if only respective commands should be documented 
        if args.skip_service_scan: return {'returncode': 0, 'name': 'run_cmd'}
        
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')

        await asyncio.wait([
            read_stream(process.stdout, target, tag=tag, patterns=patterns),
            read_stream(process.stderr, target, tag=tag, patterns=patterns, color=Fore.RED)
        ])

        await process.wait()

    if process.returncode != 0:
        error('Task {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}.')
        async with target.lock:
            with open(os.path.join(scandir, files['errors']), 'a') as file:
                file.writelines(e('[*] Task {tag} returned non-zero exit code: {process.returncode}. Command: {cmd}\n'))
    else:
        info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully.')

    return {'returncode': process.returncode, 'name': 'run_cmd'}

async def parse_port_scan(stream, tag, target, pattern):
    address = target.address
    ports = []

    while True:
        line = await stream.readline()
        if line:
            line = str(line.rstrip(), 'utf8', 'ignore')
            debug(Fore.BLUE + '[' + Style.BRIGHT + address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=Fore.BLUE)

            parse_match = re.search(pattern, line)
            if parse_match:
                ports.append(parse_match.group('port'))

            for p in global_patterns:
                matches = re.findall(p['pattern'], line)
                if 'description' in p:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(e('{tag} - ' + p['description'] + '\n\n'))
                else:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(e('{tag} - Matched Pattern: {match}\n\n'))
        else:
            break

    return ports

async def parse_service_detection(stream, tag, target, pattern):
    address = target.address
    services = []

    while True:
        line = await stream.readline()
        if line:
            line = str(line.rstrip(), 'utf8', 'ignore')
            debug(Fore.BLUE + '[' + Style.BRIGHT + address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=Fore.BLUE)

            parse_match = re.search(pattern, line)
            if parse_match:
                services.append((parse_match.group('protocol').lower(), int(parse_match.group('port')), parse_match.group('service')))

            for p in global_patterns:
                matches = re.findall(p['pattern'], line)
                if 'description' in p:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(e('{tag} - ' + p['description'] + '\n\n'))
                else:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, files['patterns']), 'a') as file:
                                file.writelines(e('{tag} - Matched Pattern: {match}\n\n'))
        else:
            break

    return services

async def run_portscan(semaphore, tag, target, service_detection, port_scan=None):
    async with semaphore:

        address = target.address
        scandir = target.scandir
        nmap_extra = nmap_default_options

        ports = ''
        if port_scan is not None:
            command = e(port_scan[0])
            pattern = port_scan[1]

            info('Running port scan {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}.' if verbose >= 1 else '.'))

            async with target.lock:
                with open(os.path.join(scandir, files['commands']), 'a') as file:
                    file.writelines(e('{command}\n\n'))

            process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')

            output = [
                parse_port_scan(process.stdout, tag, target, pattern),
                read_stream(process.stderr, target, tag=tag, color=Fore.RED)
            ]

            results = await asyncio.gather(*output)
            
            await process.wait()
            
            if process.returncode != 0:
                error('Port scan {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
                async with target.lock:
                    with open(os.path.join(scandir, files['errors']), 'a') as file:
                        file.writelines(e('[*] Port scan {tag} returned non-zero exit code: {process.returncode}. Command: {command}\n'))
                return {'returncode': process.returncode}
            else:
                info('Port scan {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully')

            ports = results[0]
            if len(ports) == 0:
                return {'returncode': -1}

            ports = ','.join(ports)

        command = e(service_detection[0])
        pattern = service_detection[1]

        info('Running service detection {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}.' if verbose >= 1 else '.'))

        async with target.lock:
            with open(os.path.join(scandir, files['commands']), 'a') as file:
                file.writelines(e('{command}\n\n'))

        process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')

        output = [
            parse_service_detection(process.stdout, tag, target, pattern),
            read_stream(process.stderr, target, tag=tag, color=Fore.RED)
        ]

        results = await asyncio.gather(*output)

        await process.wait()

        if process.returncode != 0:
            error('Service detection {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
            async with target.lock:
                with open(os.path.join(scandir, files['errors']), 'a') as file:
                    file.writelines(e('[*] Service detection {tag} returned non-zero exit code: {process.returncode}. Command: {command}\n'))
        else:
            info('Service detection {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully.')

        services = results[0]

        return {'returncode': process.returncode, 'name': 'run_portscan', 'services': services}

async def scan_services(loop, semaphore, target):
    address = target.address
    scandir = target.scandir
    pending = []

    for profile in port_scan_profiles_config:
        if profile == port_scan_profile:
            for scan in port_scan_profiles_config[profile]:
                service_detection = (port_scan_profiles_config[profile][scan]['service-detection']['command'], port_scan_profiles_config[profile][scan]['service-detection']['pattern'])
                if 'port-scan' in port_scan_profiles_config[profile][scan]:
                    port_scan = (port_scan_profiles_config[profile][scan]['port-scan']['command'], port_scan_profiles_config[profile][scan]['port-scan']['pattern'])
                    pending.append(run_portscan(semaphore, scan, target, service_detection, port_scan))
                else:
                    pending.append(run_portscan(semaphore, scan, target, service_detection))
            break

    services = []

    while True:
        if not pending:
            break
        
        done, pending = await asyncio.wait(pending, return_when=FIRST_COMPLETED)

        for task in done:
            result = task.result()
            if result['returncode'] == 0:
                if result['name'] == 'run_portscan':
                    for service_tuple in result['services']:
                        if service_tuple not in services:
                            services.append(service_tuple)
                        else:
                            continue

                        protocol = service_tuple[0]
                        port = service_tuple[1]
                        service = service_tuple[2]

                        info('Port {bmagenta}{protocol} {port}{rst} ({bmagenta}{service}{rst}) open on target {byellow}{address}{rst}.')

                        with open(os.path.join(target.scandir, files['notes']), 'a') as file:
                            file.writelines(e('[*] Port {protocol} {port} ({service}) open on {address}.\n\n'))

                        if protocol == 'udp':
                            nmap_extra = nmap_default_options + " -sU"
                        else:
                            nmap_extra = nmap_default_options

                        secure = True if 'ssl' in service or 'tls' in service else False

                        # Special cases for HTTP.
                        scheme = 'https' if 'https' in service or 'ssl' in service or 'tls' in service else 'http'

                        if service.startswith('ssl/') or service.startswith('tls/'):
                            service = service[4:]

                        for service_scan in service_scans_config:
                            # Skip over configurable variables since the python toml parser cannot iterate over tables only.
                            if service_scan in ['username_wordlist', 'password_wordlist']:
                                continue

                            ignore_service = False
                            if 'ignore-service-names' in service_scans_config[service_scan]:
                                for ignore_service_name in service_scans_config[service_scan]['ignore-service-names']:
                                    if re.search(ignore_service_name, service):
                                        ignore_service = True
                                        break

                            if ignore_service:
                                continue

                            matched_service = False

                            if 'service-names' in service_scans_config[service_scan]:
                                for service_name in service_scans_config[service_scan]['service-names']:
                                    if re.search(service_name, service):
                                        matched_service = True
                                        break

                            if not matched_service:
                                continue

                            # INFO: change for saving results in directories per service
                            if not service_scan == 'all-services':
                                category = '{0}/'.format(service_scan) 
                            else:
                                category = ''
                            
                            try:
                                servicedir = os.path.join(scandir, category)
                                if not os.path.exists(servicedir): os.mkdir(servicedir)
                                xmldir = os.path.join(scandir, 'xml', category)
                                if not os.path.exists(xmldir): os.mkdir(xmldir)
                            except OSError:
                                category = ''

                            if 'manual' in service_scans_config[service_scan]:
                                heading = False
                                with open(os.path.join(scandir, files['manual_commands']), 'a') as file:
                                    for manual in service_scans_config[service_scan]['manual']:
                                        if 'description' in manual:
                                            if not heading:
                                                file.writelines(e('[*] {service} on {protocol}/{port}\n\n'))
                                                heading = True
                                            description = manual['description']
                                            file.writelines(e('\t[-] {description}\n\n'))
                                        if 'commands' in manual:
                                            if not heading:
                                                file.writelines(e('[*] {service} on {protocol}/{port}\n\n'))
                                                heading = True
                                            for manual_command in manual['commands']:
                                                manual_command = e(manual_command)
                                                file.writelines('\t\t' + e('{manual_command}\n\n'))
                                    if heading:
                                        file.writelines('\n')

                            if 'scan' in service_scans_config[service_scan]:
                                for scan in service_scans_config[service_scan]['scan']:
                                    if 'name' in scan:
                                        name = scan['name']
                                        
                                        # INFO: change for supporting different complexity levels during service scanning
                                        run_level = scan['level'] if 'level' in scan else 0
                                        if (not args.run_only and run_level > max(args.run_level)) or (args.run_only and not run_level in args.run_level):    
                                            if verbose >= 1:
                                                info('Scan profile {bgreen}{name}{rst} is at a {bgree}different complexity level{rst} and is ignored.')
                                            continue

                                        if 'command' in scan:
                                            tag = e('{protocol}/{port}/{name}')
                                            command = scan['command']

                                            if 'ports' in scan:
                                                port_match = False

                                                if protocol == 'tcp':
                                                    if 'tcp' in scan['ports']:
                                                        for tcp_port in scan['ports']['tcp']:
                                                            if port == tcp_port:
                                                                port_match = True
                                                                break
                                                elif protocol == 'udp':
                                                    if 'udp' in scan['ports']:
                                                        for udp_port in scan['ports']['udp']:
                                                            if port == udp_port:
                                                                port_match = True
                                                                break

                                                if port_match == False:
                                                    warn(Fore.YELLOW + '[' + Style.BRIGHT + tag + Style.NORMAL + '] Scan cannot be run against {protocol} port {port}. Skipping.' + Fore.RESET)
                                                    continue

                                            if 'run_once' in scan and scan['run_once'] == True:
                                                scan_tuple = (name,)
                                                if scan_tuple in target.scans:
                                                    warn(Fore.YELLOW + '[' + Style.BRIGHT + tag + ' on ' + address + Style.NORMAL + '] Scan should only be run once and it appears to have already been queued. Skipping.' + Fore.RESET)
                                                    continue
                                                else:
                                                    target.scans.append(scan_tuple)
                                            else:
                                                scan_tuple = (protocol, port, service, name)
                                                if scan_tuple in target.scans:
                                                    warn(Fore.YELLOW + '[' + Style.BRIGHT + tag + ' on ' + address + Style.NORMAL + '] Scan appears to have already been queued, but it is not marked as run_once in service-scans.toml. Possible duplicate tag? Skipping.' + Fore.RESET)
                                                    continue
                                                else:
                                                    target.scans.append(scan_tuple)

                                            patterns = []
                                            if 'pattern' in scan:
                                                patterns = scan['pattern']

                                            pending.add(asyncio.ensure_future(run_cmd(semaphore, e(command), target, category=category, tag=tag, patterns=patterns)))

#        if not args.no_report:
#            pending.add(asyncio.ensure_future(create_report(semaphore, target)))

def scan_host(target, concurrent_scans):
    info('Scanning target {byellow}{target.address}{rst}.')
    
    basedir = os.path.abspath(os.path.join(outdir, target.address + srvname))
    target.basedir = basedir
    os.makedirs(basedir, exist_ok=True)

    exploitdir = os.path.abspath(os.path.join(basedir, 'exploit'))
    os.makedirs(exploitdir, exist_ok=True)
    
    exploitdir = os.path.abspath(os.path.join(basedir, 'privilege_escalation'))
    os.makedirs(exploitdir, exist_ok=True)

    lootdir = os.path.abspath(os.path.join(basedir, 'loot'))
    os.makedirs(lootdir, exist_ok=True)

    reportdir = os.path.abspath(os.path.join(basedir, 'report'))
    target.reportdir = reportdir
    os.makedirs(reportdir, exist_ok=True)

    screenshotdir = os.path.abspath(os.path.join(reportdir, 'screenshots'))
    os.makedirs(screenshotdir, exist_ok=True)

    scandir = os.path.abspath(os.path.join(basedir, 'scans'))
    target.scandir = scandir
    os.makedirs(scandir, exist_ok=True)
    prepare_log_files(scandir, target)

    os.makedirs(os.path.abspath(os.path.join(scandir, 'xml')), exist_ok=True)

    open(os.path.abspath(os.path.join(reportdir, 'local.txt')), 'a').close()
    open(os.path.abspath(os.path.join(reportdir, 'proof.txt')), 'a').close()

    # Use a lock when writing to specific files that may be written to by other asynchronous functions.
    target.lock = asyncio.Lock()

    # Get event loop for current process.
    loop = asyncio.get_event_loop()

    # Create a semaphore to limit number of concurrent scans.
    semaphore = asyncio.Semaphore(concurrent_scans)

    try:
        loop.run_until_complete(scan_services(loop, semaphore, target))
        info('Finished scanning target {byellow}{target.address}{rst}.')
        
        if not args.no_report:
            loop.run_until_complete(create_report(target)) 
    except KeyboardInterrupt:
        sys.exit(1)

async def create_report(target):
    address = target.address
    scandir = target.scandir
    reportdir = target.reportdir

    #types = ('*.txt') 
    #filenames = []
    #[filenames.extend(glob.glob(os.path.join(scandir, '*', filetype), recursive=True)) for filetype in types]
    filenames = glob.glob(os.path.join(scandir, '**', '*.txt'), recursive=True)
    filenames.sort()
    report_order = ' '.join(filenames)
    
    # TODO: make us of config file
    cmd = '/usr/bin/enscript {0} -o - | /usr/bin/ps2pdf - {1}'.format(report_order, os.path.join(reportdir, files['report']))

    info('Creating report for target {byellow}{address}{rst}.')
    process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')
    await process.communicate()
    
    if process.returncode != 0:
        error('{bred}Report creation{rst} for target {byellow}{address}{rst} returned non-zero exit code: {process.returncode}.')
    else:
        info('Report for target {byellow}{address}{rst} was created successfully.')

def prepare_log_files(scandir, target):

    for filename in files:
        try:
            caption = 'Log session started for host {0} - {1}\n'.format(target.address, datetime.now().strftime('%B %d, %Y - %H:%M:%S'))
            with open(os.path.join(scandir, files[filename]), 'a') as f:
                f.write('\n{}\n'.format('=' * len(caption)))
                f.write(caption)
                f.write('{}\n\n'.format('=' * len(caption)))
        except OSError:
            fail('Error while setting up log file {filename}.')

def read_targets_from_file(filename, targets, disable_sanity_checks):

    if not os.path.isfile(filename):
        error('The file {filename} with target information was not found.')
        return (targets, True)

    try:
        with open(filename, 'r') as f:
            entries = f.read()
    except OSError:
        error('The file {filename} with target information could not be read.')
        return (targets, True)

    error = False
    for ip in entries.split('\n'):
        if ip.startswith('#') or len(ip) == 0: continue
        
        targets, failed = get_ip_address(ip, targets, disable_sanity_checks)
        if failed: error = True
    
    return (targets, error)

def get_ip_address(target, targets, disable_sanity_checks):

    errors = False
    try:
        ip = str(ipaddress.ip_address(target))

        if ip not in targets:
            targets.append(ip)
    except ValueError:
        try:
            target_range = ipaddress.ip_network(target, strict=False)
            if not disable_sanity_checks and target_range.num_addresses > 256:
                error(target + ' contains ' + str(target_range.num_addresses) + ' addresses. Check that your CIDR notation is correct. If it is, re-run with the --disable-sanity-checks option to suppress this check.')
                errors = True
            else:
                for ip in target_range.hosts():
                    ip = str(ip)
                    if ip not in targets:
                        targets.append(ip)
        except ValueError:
            try:
                ip = socket.gethostbyname(target)
                if target not in targets:
                    targets.append(target)
            except socket.gaierror:
                warn(target + ' does not appear to be a valid IP address, IP range, or resolvable hostname.')

    return (targets, errors)

def get_header():

    logo = r'''
           _____          __        __________                            
          /  _  \  __ ___/  |_  ____\______   \ ____   ____  ____   ____  
         /  /_\  \|  |  \   __\/  _ \|       _// __ \_/ ___\/  _ \ /    \ 
        /    |    \  |  /|  | (  <_> )    |   \  ___/\  \__(  <_> )   |  \
        \____|__  /____/ |__|  \____/|____|_  /\___  >\___  >____/|___|  /
                \/                          \/     \/     \/           \/ 
    '''

    print('\n{0}'.format('-' * 85))
    print('{0}'.format(logo))
    print('{0} v{1}'.format(' ' * (85 - len(__version__) - 2), __version__))
    print('\n\tAutomated network reconnaissance and service enumeration.')
    print('\n{0}\n\n'.format('-' * 85))


class Target:
    def __init__(self, address):
        self.address = address
        self.basedir = ''
        self.reportdir = ''
        self.scandir = ''
        self.scans = []
        self.lock = None

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Network reconnaissance tool to port scan and automatically enumerate services found on multiple targets.', epilog = get_header())
    parser.add_argument('targets', action='store', help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.', nargs="*")
    parser.add_argument('-ct', '--concurrent-targets', action='store', metavar='<number>', type=int, default=5, help='The maximum number of target hosts to scan concurrently. Default: %(default)s')
    parser.add_argument('-cs', '--concurrent-scans', action='store', metavar='<number>', type=int, default=10, help='The maximum number of scans to perform per target host. Default: %(default)s')
    parser.add_argument('--profile', action='store', default='default', help='The port scanning profile to use (defined in port-scan-profiles.toml). Default: %(default)s')
    parser.add_argument('-o', '--output', action='store', default='results', help='The output directory for results. Default: %(default)s')
    nmap_group = parser.add_mutually_exclusive_group()
    nmap_group.add_argument('--nmap', action='store', default=nmap_default_options, help='Override the {nmap_extra} variable in scans. Default: %(default)s')
    nmap_group.add_argument('--nmap-append', action='store', default='', help='Append to the default {nmap_extra} variable in scans.')
    parser.add_argument('--skip-service-scan', action='store_true', default=False, help='Do not perfom extended service scanning but only document commands.')
    parser.add_argument('--run-level', action='store', type=int, default=[0], nargs="+", help='During extended service scanning, only run scanners of a certain complexity level or below.')
    parser.add_argument('--run-only', action='store_true', default=False, help='If enabled, only run scanners of the specified complexity level during extended service scanning.')
    parser.add_argument('-r', '--read', action='store', type=str, default='', dest='target_file', help='Read targets from file.')
    parser.add_argument('--no-report', action='store_true', default=False, help='Do not create a summary report after completing scanning a target.')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Enable verbose output. Repeat for more verbosity.')
    parser.add_argument('--disable-sanity-checks', action='store_true', default=False, help='Disable sanity checks that would otherwise prevent the scans from running.')
    parser.error = lambda s: fail(s[0].upper() + s[1:])
    args = parser.parse_args()

    if not os.getuid() == 0:
        warn('Warning: You are not running the program with superuser privileges. Service scanning may be impacted.')

    config_loaded = get_configuration()
    if not config_loaded: sys.exit(-1)

    errors = False

    if args.concurrent_targets <= 0:
        error('Argument -ch/--concurrent-targets: must be at least 1.')
        errors = True

    concurrent_scans = args.concurrent_scans

    if concurrent_scans <= 0:
        error('Argument -ct/--concurrent-scans: must be at least 1.')
        errors = True

    if min(args.run_level) < 0 or max(args.run_level) > max_level:
        error('Argument --run-level: must be between 0 (default) and {}.'.format(max_level))
        errors = True

    port_scan_profile = args.profile

    found_scan_profile = False
    for profile in port_scan_profiles_config:
        if profile == port_scan_profile:
            found_scan_profile = True
            for scan in port_scan_profiles_config[profile]:
                if 'service-detection' not in port_scan_profiles_config[profile][scan]:
                    error('The {profile}.{scan} scan does not have a defined service-detection section. Every scan must at least have a service-detection section defined with a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the result.')
                    errors = True
                else:
                    if 'command' not in port_scan_profiles_config[profile][scan]['service-detection']:
                        error('The {profile}.{scan}.service-detection section does not have a command defined. Every service-detection section must have a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the results.')
                        errors = True
                    else:
                        if '{ports}' in port_scan_profiles_config[profile][scan]['service-detection']['command'] and 'port-scan' not in port_scan_profiles_config[profile][scan]:
                            error('The {profile}.{scan}.service-detection command appears to reference a port list but there is no port-scan section defined in {profile}.{scan}. Define a port-scan section with a command and corresponding pattern that extracts port numbers from the result, or replace the reference with a static list of ports.')
                            errors = True

                    if 'pattern' not in port_scan_profiles_config[profile][scan]['service-detection']:
                        error('The {profile}.{scan}.service-detection section does not have a pattern defined. Every service-detection section must have a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the results.')
                        errors = True
                    else:
                        if not all(x in port_scan_profiles_config[profile][scan]['service-detection']['pattern'] for x in ['(?P<port>', '(?P<protocol>', '(?P<service>']):
                            error('The {profile}.{scan}.service-detection pattern does not contain one or more of the following matching groups: port, protocol, service. Ensure that all three of these matching groups are defined and capture the relevant data, e.g. (?P<port>\d+)')
                            errors = True

                if 'port-scan' in port_scan_profiles_config[profile][scan]:
                    if 'command' not in port_scan_profiles_config[profile][scan]['port-scan']:
                        error('The {profile}.{scan}.port-scan section does not have a command defined. Every port-scan section must have a command and a corresponding pattern that extracts the port from the results.')
                        errors = True

                    if 'pattern' not in port_scan_profiles_config[profile][scan]['port-scan']:
                        error('The {profile}.{scan}.port-scan section does not have a pattern defined. Every port-scan section must have a command and a corresponding pattern that extracts the port from the results.')
                        errors = True
                    else:
                        if '(?P<port>' not in port_scan_profiles_config[profile][scan]['port-scan']['pattern']:
                            error('The {profile}.{scan}.port-scan pattern does not contain a port matching group. Ensure that the port matching group is defined and captures the relevant data, e.g. (?P<port>\d+)')
                            errors = True
            break

    if not found_scan_profile:
        error('Argument --profile: must reference a port scan profile defined in {port_scan_profiles_config_file}. No such profile found: {port_scan_profile}')
        errors = True

    nmap_default_options = args.nmap
    if args.nmap_append:
        nmap_default_options += " " + args.nmap_append

    outdir = args.output
    srvname = ''
    verbose = args.verbose

    if len(args.targets) == 0 and not len(args.target_file):
        error('You must specify at least one target to scan!')
        errors = True

    targets = []

    for target in args.targets:
        targets, failed = get_ip_address(target, targets, args.disable_sanity_checks)
        if failed: errors = True

    if len(args.target_file) > 0:
        targets, errors = read_targets_from_file(args.target_file, targets, args.disable_sanity_checks)

    if not args.disable_sanity_checks and len(targets) > 256:
        error('A total of ' + str(len(targets)) + ' targets would be scanned. If this is correct, re-run with the --disable-sanity-checks option to suppress this check.')
        errors = True

    if errors:
        sys.exit(1)

    start_timer = datetime.now().strftime('%H:%M:%S')
    with ProcessPoolExecutor(max_workers=args.concurrent_targets) as executor:
        futures = []

        for address in targets:
            target = Target(address)
            futures.append(executor.submit(scan_host, target, concurrent_scans))

        try:
            for future in as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False)
            sys.exit(1)
    end_timer = datetime.now().strftime('%H:%M:%S')
    tdelta = datetime.strptime(end_timer, '%H:%M:%S') - datetime.strptime(start_timer, '%H:%M:%S')
    print('\nScanning completed in {}.'.format(tdelta))

    
