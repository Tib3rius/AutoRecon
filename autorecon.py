#!/usr/bin/env python3
#
#    AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services.
#
#    This program can be redistributed and/or modified under the terms of the
#    GNU General Public License, either version 3 of the License, or (at your
#    option) any later version.
#

import atexit
import argparse
import asyncio
import colorama
from colorama import Fore, Style
from concurrent.futures import ProcessPoolExecutor, as_completed, FIRST_COMPLETED
from datetime import datetime
import ipaddress
import os
import re
import socket
import string
import sys
import time
import toml
import termios

def _quit():
    termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, TERM_FLAGS)

atexit.register(_quit)

TERM_FLAGS = termios.tcgetattr(sys.stdin.fileno())

verbose = 0
nmap = '-vv --reason -Pn'
srvname = ''
heartbeat_interval = 60
port_scan_profile = None

port_scan_profiles_config = None
service_scans_config = None
global_patterns = []

username_wordlist = '/usr/share/seclists/Usernames/top-usernames-shortlist.txt'
password_wordlist = '/usr/share/seclists/Passwords/darkweb2017-top100.txt'

rootdir = os.path.dirname(os.path.realpath(__file__))

single_target = False
only_scans_dir = False

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

    unfmt = ''
    if char is not None:
        unfmt += color + '[' + Style.BRIGHT + char + Style.NORMAL + ']' + Fore.RESET + sep
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

def calculate_elapsed_time(start_time):
    elapsed_seconds = round(time.time() - start_time)

    m, s = divmod(elapsed_seconds, 60)
    h, m = divmod(m, 60)

    elapsed_time = []
    if h == 1:
        elapsed_time.append(str(h) + ' hour')
    elif h > 1:
        elapsed_time.append(str(h) + ' hours')

    if m == 1:
        elapsed_time.append(str(m) + ' minute')
    elif m > 1:
        elapsed_time.append(str(m) + ' minutes')

    if s == 1:
        elapsed_time.append(str(s) + ' second')
    elif s > 1:
        elapsed_time.append(str(s) + ' seconds')
    else:
        elapsed_time.append('less than a second')

    return ', '.join(elapsed_time)

port_scan_profiles_config_file = 'port-scan-profiles.toml'
with open(os.path.join(rootdir, 'config', port_scan_profiles_config_file), 'r') as p:
    try:
        port_scan_profiles_config = toml.load(p)

        if len(port_scan_profiles_config) == 0:
            fail('There do not appear to be any port scan profiles configured in the {port_scan_profiles_config_file} config file.')

    except toml.decoder.TomlDecodeError as e:
        fail('Error: Couldn\'t parse {port_scan_profiles_config_file} config file. Check syntax and duplicate tags.')

with open(os.path.join(rootdir, 'config', 'service-scans.toml'), 'r') as c:
    try:
        service_scans_config = toml.load(c)
    except toml.decoder.TomlDecodeError as e:
        fail('Error: Couldn\'t parse service-scans.toml config file. Check syntax and duplicate tags.')

with open(os.path.join(rootdir, 'config', 'global-patterns.toml'), 'r') as p:
    try:
        global_patterns = toml.load(p)
        if 'pattern' in global_patterns:
            global_patterns = global_patterns['pattern']
        else:
            global_patterns = []
    except toml.decoder.TomlDecodeError as e:
        fail('Error: Couldn\'t parse global-patterns.toml config file. Check syntax and duplicate tags.')

if 'username_wordlist' in service_scans_config:
    if isinstance(service_scans_config['username_wordlist'], str):
        username_wordlist = service_scans_config['username_wordlist']

if 'password_wordlist' in service_scans_config:
    if isinstance(service_scans_config['password_wordlist'], str):
        password_wordlist = service_scans_config['password_wordlist']

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
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - ' + p['description'] + '\n\n'))
                else:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - Matched Pattern: {match}\n\n'))

            for p in patterns:
                matches = re.findall(p['pattern'], line)
                if 'description' in p:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}' + p['description'].replace('{match}', '{bblue}{match}{crst}{bmagenta}') + '{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - ' + p['description'] + '\n\n'))
                else:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - Matched Pattern: {match}\n\n'))
        else:
            break

async def run_cmd(semaphore, cmd, target, tag='?', patterns=[]):
    async with semaphore:
        address = target.address
        scandir = target.scandir

        info('Running task {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{cmd}{rst}' if verbose >= 1 else ''))

        async with target.lock:
            with open(os.path.join(scandir, '_commands.log'), 'a') as file:
                file.writelines(e('{cmd}\n\n'))

        start_time = time.time()
        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')
        async with target.lock:
            target.running_tasks.append(tag)

        await asyncio.wait([
            read_stream(process.stdout, target, tag=tag, patterns=patterns),
            read_stream(process.stderr, target, tag=tag, patterns=patterns, color=Fore.RED)
        ])

        await process.wait()
        async with target.lock:
            target.running_tasks.remove(tag)
        elapsed_time = calculate_elapsed_time(start_time)

    if process.returncode != 0:
        error('Task {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
        async with target.lock:
            with open(os.path.join(scandir, '_errors.log'), 'a') as file:
                file.writelines(e('[*] Task {tag} returned non-zero exit code: {process.returncode}. Command: {cmd}\n'))
    else:
        info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully in {elapsed_time}')

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
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - ' + p['description'] + '\n\n'))
                else:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
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
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - ' + p['description'] + '\n\n'))
                else:
                    for match in matches:
                        if verbose >= 1:
                            info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} - {bmagenta}Matched Pattern: {bblue}{match}{rst}')
                        async with target.lock:
                            with open(os.path.join(target.scandir, '_patterns.log'), 'a') as file:
                                file.writelines(e('{tag} - Matched Pattern: {match}\n\n'))
        else:
            break

    return services

async def run_portscan(semaphore, tag, target, service_detection, port_scan=None):
    async with semaphore:

        address = target.address
        scandir = target.scandir
        nmap_extra = nmap

        ports = ''
        if port_scan is not None:
            command = e(port_scan[0])
            pattern = port_scan[1]

            info('Running port scan {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}' if verbose >= 1 else ''))

            async with target.lock:
                with open(os.path.join(scandir, '_commands.log'), 'a') as file:
                    file.writelines(e('{command}\n\n'))

            start_time = time.time()
            process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')
            async with target.lock:
                target.running_tasks.append(tag)

            output = [
                parse_port_scan(process.stdout, tag, target, pattern),
                read_stream(process.stderr, target, tag=tag, color=Fore.RED)
            ]

            results = await asyncio.gather(*output)

            await process.wait()
            async with target.lock:
                target.running_tasks.remove(tag)
            elapsed_time = calculate_elapsed_time(start_time)

            if process.returncode != 0:
                error('Port scan {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
                async with target.lock:
                    with open(os.path.join(scandir, '_errors.log'), 'a') as file:
                        file.writelines(e('[*] Port scan {tag} returned non-zero exit code: {process.returncode}. Command: {command}\n'))
                return {'returncode': process.returncode}
            else:
                info('Port scan {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully in {elapsed_time}')

            ports = results[0]
            if len(ports) == 0:
                return {'returncode': -1}

            ports = ','.join(ports)

        command = e(service_detection[0])
        pattern = service_detection[1]

        info('Running service detection {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}' if verbose >= 1 else ''))

        async with target.lock:
            with open(os.path.join(scandir, '_commands.log'), 'a') as file:
                file.writelines(e('{command}\n\n'))

        start_time = time.time()
        process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, executable='/bin/bash')
        async with target.lock:
            target.running_tasks.append(tag)

        output = [
            parse_service_detection(process.stdout, tag, target, pattern),
            read_stream(process.stderr, target, tag=tag, color=Fore.RED)
        ]

        results = await asyncio.gather(*output)

        await process.wait()
        async with target.lock:
            target.running_tasks.remove(tag)
        elapsed_time = calculate_elapsed_time(start_time)

        if process.returncode != 0:
            error('Service detection {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
            async with target.lock:
                with open(os.path.join(scandir, '_errors.log'), 'a') as file:
                    file.writelines(e('[*] Service detection {tag} returned non-zero exit code: {process.returncode}. Command: {command}\n'))
        else:
            info('Service detection {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully in {elapsed_time}')

        services = results[0]

        return {'returncode': process.returncode, 'name': 'run_portscan', 'services': services}

async def start_heartbeat(target, period=60):
    while True:
        await asyncio.sleep(period)
        async with target.lock:
            tasks = target.running_tasks
            count = len(tasks)

            tasks_list = ''
            if verbose >= 1:
                tasks_list = ': {bgreen}' + ', '.join(tasks) + '{rst}'

            current_time = datetime.now().strftime('%H:%M:%S')

            if count > 1:
                info('{bgreen}[{current_time}]{rst} - There are {byellow}{count}{rst} tasks still running on {byellow}{target.address}{rst}' + tasks_list)
            elif count == 1:
                info('{bgreen}[{current_time}]{rst} - There is {byellow}1{rst} task still running on {byellow}{target.address}{rst}' + tasks_list)

async def scan_services(loop, semaphore, target):
    address = target.address
    scandir = target.scandir
    pending = []

    heartbeat = loop.create_task(start_heartbeat(target, period=heartbeat_interval))

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
            heartbeat.cancel()
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

                        info('Found {bmagenta}{service}{rst} on {bmagenta}{protocol}/{port}{rst} on target {byellow}{address}{rst}')

                        if not only_scans_dir:
                            with open(os.path.join(target.reportdir, 'notes.txt'), 'a') as file:
                                file.writelines(e('[*] {service} found on {protocol}/{port}.\n\n\n\n'))

                        if protocol == 'udp':
                            nmap_extra = nmap + " -sU"
                        else:
                            nmap_extra = nmap

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

                            if 'manual' in service_scans_config[service_scan]:
                                heading = False
                                with open(os.path.join(scandir, '_manual_commands.txt'), 'a') as file:
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

                                            pending.add(asyncio.ensure_future(run_cmd(semaphore, e(command), target, tag=tag, patterns=patterns)))

def scan_host(target, concurrent_scans):
    start_time = time.time()
    info('Scanning target {byellow}{target.address}{rst}')

    if single_target:
        basedir = os.path.abspath(outdir)
    else:
        basedir = os.path.abspath(os.path.join(outdir, target.address + srvname))
    target.basedir = basedir
    os.makedirs(basedir, exist_ok=True)

    if not only_scans_dir:
        exploitdir = os.path.abspath(os.path.join(basedir, 'exploit'))
        os.makedirs(exploitdir, exist_ok=True)

        lootdir = os.path.abspath(os.path.join(basedir, 'loot'))
        os.makedirs(lootdir, exist_ok=True)

        reportdir = os.path.abspath(os.path.join(basedir, 'report'))
        target.reportdir = reportdir
        os.makedirs(reportdir, exist_ok=True)

        open(os.path.abspath(os.path.join(reportdir, 'local.txt')), 'a').close()
        open(os.path.abspath(os.path.join(reportdir, 'proof.txt')), 'a').close()

        screenshotdir = os.path.abspath(os.path.join(reportdir, 'screenshots'))
        os.makedirs(screenshotdir, exist_ok=True)

    scandir = os.path.abspath(os.path.join(basedir, 'scans'))
    target.scandir = scandir
    os.makedirs(scandir, exist_ok=True)

    os.makedirs(os.path.abspath(os.path.join(scandir, 'xml')), exist_ok=True)

    # Use a lock when writing to specific files that may be written to by other asynchronous functions.
    target.lock = asyncio.Lock()

    # Get event loop for current process.
    loop = asyncio.get_event_loop()

    # Create a semaphore to limit number of concurrent scans.
    semaphore = asyncio.Semaphore(concurrent_scans)

    try:
        loop.run_until_complete(scan_services(loop, semaphore, target))
        elapsed_time = calculate_elapsed_time(start_time)
        info('Finished scanning target {byellow}{target.address}{rst} in {elapsed_time}')
    except KeyboardInterrupt:
        sys.exit(1)

class Target:
    def __init__(self, address):
        self.address = address
        self.basedir = ''
        self.reportdir = ''
        self.scandir = ''
        self.scans = []
        self.lock = None
        self.running_tasks = []

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Network reconnaissance tool to port scan and automatically enumerate services found on multiple targets.')
    parser.add_argument('targets', action='store', help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.', nargs="*")
    parser.add_argument('-t', '--targets', action='store', type=str, default='', dest='target_file', help='Read targets from file.')
    parser.add_argument('-ct', '--concurrent-targets', action='store', metavar='<number>', type=int, default=5, help='The maximum number of target hosts to scan concurrently. Default: %(default)s')
    parser.add_argument('-cs', '--concurrent-scans', action='store', metavar='<number>', type=int, default=10, help='The maximum number of scans to perform per target host. Default: %(default)s')
    parser.add_argument('--profile', action='store', default='default', dest='profile_name', help='The port scanning profile to use (defined in port-scan-profiles.toml). Default: %(default)s')
    parser.add_argument('-o', '--output', action='store', default='results', dest='output_dir', help='The output directory for results. Default: %(default)s')
    parser.add_argument('--single-target', action='store_true', default=False, help='Only scan a single target. A directory named after the target will not be created. Instead, the directory structure will be created within the output directory. Default: false')
    parser.add_argument('--only-scans-dir', action='store_true', default=False, help='Only create the "scans" directory for results. Other directories (e.g. exploit, loot, report) will not be created. Default: false')
    parser.add_argument('--heartbeat', action='store', type=int, default=60, help='Specifies the heartbeat interval (in seconds) for task status messages. Default: %(default)s')
    nmap_group = parser.add_mutually_exclusive_group()
    nmap_group.add_argument('--nmap', action='store', default='-vv --reason -Pn', help='Override the {nmap_extra} variable in scans. Default: %(default)s')
    nmap_group.add_argument('--nmap-append', action='store', default='', help='Append to the default {nmap_extra} variable in scans.')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Enable verbose output. Repeat for more verbosity.')
    parser.add_argument('--disable-sanity-checks', action='store_true', default=False, help='Disable sanity checks that would otherwise prevent the scans from running. Default: false')
    parser.error = lambda s: fail(s[0].upper() + s[1:])
    args = parser.parse_args()

    single_target = args.single_target
    only_scans_dir = args.only_scans_dir

    errors = False

    if args.concurrent_targets <= 0:
        error('Argument -ch/--concurrent-targets: must be at least 1.')
        errors = True

    concurrent_scans = args.concurrent_scans

    if concurrent_scans <= 0:
        error('Argument -ct/--concurrent-scans: must be at least 1.')
        errors = True

    port_scan_profile = args.profile_name

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

    heartbeat_interval = args.heartbeat

    nmap = args.nmap
    if args.nmap_append:
        nmap += " " + args.nmap_append

    outdir = args.output_dir
    srvname = ''
    verbose = args.verbose

    raw_targets = args.targets
    targets = []

    if len(args.target_file) > 0:
        if not os.path.isfile(args.target_file):
            error('The target file {args.target_file} was not found.')
            sys.exit(1)
        try:
            with open(args.target_file, 'r') as f:
                lines = f.read()
                for line in lines.splitlines():
                    line = line.strip()
                    if line.startswith('#') or len(line) == 0: continue
                    if line not in raw_targets:
                        raw_targets.append(line)
        except OSError:
            error('The target file {args.target_file} could not be read.')
            sys.exit(1)

    for target in raw_targets:
        try:
            ip = str(ipaddress.ip_address(target))

            if ip not in targets:
                targets.append(ip)
        except ValueError:

            try:
                target_range = ipaddress.ip_network(target, strict=False)
                if not args.disable_sanity_checks and target_range.num_addresses > 256:
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
                    error(target + ' does not appear to be a valid IP address, IP range, or resolvable hostname.')
                    errors = True

    if len(targets) == 0:
        error('You must specify at least one target to scan!')
        errors = True

    if single_target and len(targets) != 1:
        error('You cannot provide more than one target when scanning in single-target mode.')
        sys.exit(1)

    if not args.disable_sanity_checks and len(targets) > 256:
        error('A total of ' + str(len(targets)) + ' targets would be scanned. If this is correct, re-run with the --disable-sanity-checks option to suppress this check.')
        errors = True

    if errors:
        sys.exit(1)

    with ProcessPoolExecutor(max_workers=args.concurrent_targets) as executor:
        start_time = time.time()
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

        elapsed_time = calculate_elapsed_time(start_time)
        info('{bgreen}Finished scanning all targets in {elapsed_time}!{rst}')
