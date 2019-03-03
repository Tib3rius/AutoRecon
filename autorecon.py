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
from colorama import init, Fore, Back, Style
from concurrent.futures import ProcessPoolExecutor, as_completed, FIRST_COMPLETED
import ipaddress
import os
import re
import socket
import string
import sys
import toml

verbose = 0
nmap = ''
srvname = ''
port_scan_profile = None

port_scan_profiles_config = None
service_scans_config = None

username_wordlist = '/usr/share/seclists/Usernames/top-usernames-shortlist.txt'
password_wordlist = '/usr/share/seclists/Passwords/darkweb2017-top100.txt'

__location__ = os.path.realpath(os.path.join(os.getcwd(), os.path.dirname(__file__)))

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

        'green':  Fore.GREEN,
        'red':    Fore.RED,
        'blue':   Fore.BLUE,
        'yellow': Fore.YELLOW,

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
    if verbose >= 1:
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

port_scan_profiles_config_file = 'port-scan-profiles.toml'
with open(os.path.join(__location__, port_scan_profiles_config_file), "r") as p:
    try:
        port_scan_profiles_config = toml.load(p)

        if len(port_scan_profiles_config) == 0:
            fail('There do not appear to be any port scan profiles configured in the {port_scan_profiles_config_file} config file.')

    except toml.decoder.TomlDecodeError as e:
        fail('Error: Couldn\'t parse {port_scan_profiles_config_file} config file. Check syntax and duplicate tags.')

with open(os.path.join(__location__, "service-scans.toml"), "r") as c:
    try:
        service_scans_config = toml.load(c)
    except toml.decoder.TomlDecodeError as e:
        fail('Error: Couldn\'t parse service-scans.toml config file. Check syntax and duplicate tags.')

if 'username_wordlist' in service_scans_config:
    if isinstance(service_scans_config['username_wordlist'], str):
        username_wordlist = service_scans_config['username_wordlist']

if 'password_wordlist' in service_scans_config:
    if isinstance(service_scans_config['password_wordlist'], str):
        password_wordlist = service_scans_config['password_wordlist']

async def read_stream(stream, address, tag='?', color=Fore.BLUE):
    while True:
        line = await stream.readline()
        if line:
            line = str(line.rstrip(), 'utf8', 'ignore')
            debug(color + '[' + Style.BRIGHT + address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=color)
        else:
            break

async def run_cmd(semaphore, cmd, target, tag='?'):
    async with semaphore:
        address = target.address
        scandir = target.scandir

        info('Running task {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{cmd}{rst}' if verbose >= 1 else ''))

        with open(os.path.join(scandir, '_commands.log'), 'a') as file:
            file.writelines(e('{cmd}\n\n'))

        process = await asyncio.create_subprocess_shell(cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        await asyncio.wait([
            read_stream(process.stdout, address, tag),
            read_stream(process.stderr, address, tag, Fore.RED)
        ])

        await process.wait()

    if process.returncode != 0:
        error('Task {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
        with open(os.path.join(scandir, '_errors.log'), 'a') as file:
            file.writelines(e('[*] Task {tag} returned non-zero exit code: {process.returncode}. Command: {cmd}\n'))
    else:
        info('Task {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully')

    return {'returncode': process.returncode, 'name': 'run_cmd'}

async def parse_port_scan(stream, tag, address, pattern):
    ports = []

    while True:
        line = await stream.readline()
        if line:
            line = str(line.rstrip(), 'utf8', 'ignore')
            debug(Fore.BLUE + '[' + Style.BRIGHT + address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=Fore.BLUE)

            parse_match = re.search(pattern, line)
            if parse_match:
                ports.append(parse_match.group('port'))
        else:
            break

    return ports

async def parse_service_detection(stream, tag, address, pattern):
    services = []

    while True:
        line = await stream.readline()
        if line:
            line = str(line.rstrip(), 'utf8', 'ignore')
            debug(Fore.BLUE + '[' + Style.BRIGHT + address + ' ' + tag + Style.NORMAL + '] ' + Fore.RESET + '{line}', color=Fore.BLUE)

            parse_match = re.search(pattern, line)
            if parse_match:
                services.append((parse_match.group('protocol').lower(), int(parse_match.group('port')), parse_match.group('service')))
        else:
            break

    return services

async def run_portscan(semaphore, tag, target, service_detection, port_scan=None):
    async with semaphore:

        address = target.address
        scandir = target.scandir

        ports = ''
        if port_scan is not None:
            command = e(port_scan[0])
            pattern = port_scan[1]

            info('Running port scan {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}' if verbose >= 1 else ''))

            with open(os.path.join(scandir, '_commands.log'), 'a') as file:
                file.writelines(e('{command}\n\n'))

            process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

            output = [
                parse_port_scan(process.stdout, tag, address, pattern),
                read_stream(process.stderr, address, tag, Fore.RED)
            ]

            results = await asyncio.gather(*output)

            await process.wait()

            if process.returncode != 0:
                error('Port scan {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
                with open(os.path.join(scandir, '_errors.log'), 'a') as file:
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

        info('Running service detection {bgreen}{tag}{rst} on {byellow}{address}{rst}' + (' with {bblue}{command}{rst}' if verbose >= 1 else ''))

        with open(os.path.join(scandir, '_commands.log'), 'a') as file:
            file.writelines(e('{command}\n\n'))

        process = await asyncio.create_subprocess_shell(command, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)

        output = [
            parse_service_detection(process.stdout, tag, address, pattern),
            read_stream(process.stderr, address, tag, Fore.RED)
        ]

        results = await asyncio.gather(*output)

        await process.wait()

        if process.returncode != 0:
            error('Service detection {bred}{tag}{rst} on {byellow}{address}{rst} returned non-zero exit code: {process.returncode}')
            with open(os.path.join(scandir, '_errors.log'), 'a') as file:
                file.writelines(e('[*] Service detection {tag} returned non-zero exit code: {process.returncode}. Command: {command}\n'))
        else:
            info('Service detection {bgreen}{tag}{rst} on {byellow}{address}{rst} finished successfully')

        services = results[0]

        return {'returncode': process.returncode, 'name': 'run_portscan', 'services': services}

async def scan_services(loop, semaphore, target):
    global nmap
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

                        info(Fore.BLUE + '[' + Style.BRIGHT + address + Style.NORMAL + '] {service} found on {protocol}/{port}'  + Fore.RESET)

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
                                        if 'description' in service_scans_config[service_scan]['manual'][manual]:
                                            if not heading:
                                                file.writelines(e('[*] {service} on {protocol}/{port}\n\n'))
                                                heading = True
                                            description = service_scans_config[service_scan]['manual'][manual]['description']
                                            file.writelines(e('\t[-] {description}\n\n'))
                                        if 'commands' in service_scans_config[service_scan]['manual'][manual]:
                                            if not heading:
                                                file.writelines(e('[*] {service} on {protocol}/{port}\n\n'))
                                                heading = True
                                            for manual_command in service_scans_config[service_scan]['manual'][manual]['commands']:
                                                manual_command = e(manual_command)
                                                file.writelines('\t\t' + e('{manual_command}\n\n'))
                                    if heading:
                                        file.writelines('\n')

                            if 'scans' in service_scans_config[service_scan]:
                                for scan in service_scans_config[service_scan]['scans']:

                                    if 'command' in service_scans_config[service_scan]['scans'][scan]:
                                        tag = e('{protocol}/{port}/{scan}')
                                        command = service_scans_config[service_scan]['scans'][scan]['command']

                                        if 'ports' in service_scans_config[service_scan]['scans'][scan]:
                                            port_match = False

                                            if protocol == 'tcp':
                                                if 'tcp' in service_scans_config[service_scan]['scans'][scan]['ports']:
                                                    for tcp_port in service_scans_config[service_scan]['scans'][scan]['ports']['tcp']:
                                                        if port == tcp_port:
                                                            port_match = True
                                                            break
                                            elif protocol == 'udp':
                                                if 'udp' in service_scans_config[service_scan]['scans'][scan]['ports']:
                                                    for udp_port in service_scans_config[service_scan]['scans'][scan]['ports']['udp']:
                                                        if port == udp_port:
                                                            port_match = True
                                                            break

                                            if port_match == False:
                                                warn(Fore.YELLOW + '[' + Style.BRIGHT + tag + Style.NORMAL + '] Scan cannot be run against {protocol} port {port}. Skipping.' + Fore.RESET)
                                                continue

                                        #scan_tuple = (protocol, port, service, scan)
                                        if 'run_once' in service_scans_config[service_scan]['scans'][scan] and service_scans_config[service_scan]['scans'][scan]['run_once'] == True:
                                            scan_tuple = (service, scan)
                                            if scan_tuple in target.scans:
                                                warn(Fore.YELLOW + '[' + Style.BRIGHT + tag + ' on ' + address + Style.NORMAL + '] Scan should only be run once and it appears to have already been queued. Skipping.' + Fore.RESET)
                                                continue
                                            else:
                                                target.scans.append(scan_tuple)
                                        else:
                                            scan_tuple = (protocol, port, service, scan)
                                            if scan_tuple in target.scans:
                                                warn(Fore.YELLOW + '[' + Style.BRIGHT + tag + ' on ' + address + Style.NORMAL + '] Scan appears to have already been queued, but it is not marked as run_once in service-scans.toml. Possible duplicate tag? Skipping.' + Fore.RESET)
                                                continue
                                            else:
                                                target.scans.append(scan_tuple)

                                        pending.add(asyncio.ensure_future(run_cmd(semaphore, e(command), target, tag)))

    loop.stop()

def scan_host(target, concurrent_scans):
    info('Scanning target {byellow}{target.address}{rst}')

    basedir = os.path.abspath(os.path.join(outdir, target.address + srvname))
    target.basedir = basedir
    os.makedirs(basedir, exist_ok=True)

    exploitdir = os.path.abspath(os.path.join(basedir, 'exploit'))
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

    open(os.path.abspath(os.path.join(reportdir, 'local.txt')), 'a').close()
    open(os.path.abspath(os.path.join(reportdir, 'proof.txt')), 'a').close()

    # Get event loop for current process.
    loop = asyncio.get_event_loop()

    # Create a semaphore to limit number of concurrent scans.
    semaphore = asyncio.Semaphore(concurrent_scans)

    try:
        loop.create_task(scan_services(loop, semaphore, target))
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.close()
        info('Finished scanning target {byellow}{target.address}{rst}')
        return

class Target:
    def __init__(self, address):
        self.address = address
        self.basedir = ''
        self.reportdir = ''
        self.scandir = ''
        self.scans = []

def valid_scan_profile(port_scan_profile, port_scan_profiles_config):
    errors = False
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
    return not errors

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Network reconnaissance tool to port scan and automatically enumerate services found on multiple targets.')
    parser.add_argument('targets', action='store', help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.', nargs="+")
    parser.add_argument('-ct', '--concurrent-targets', action='store', metavar='<number>', type=int, default=5, help='The maximum number of target hosts to scan concurrently. Default: %(default)s')
    parser.add_argument('-cs', '--concurrent-scans', action='store', metavar='<number>', type=int, default=10, help='The maximum number of scans to perform per target host. Default: %(default)s')
    parser.add_argument('--profile', action='store', default='default', help='The port scanning profile to use (defined in port-scan-profiles.toml).')
    parser.add_argument('-v', '--verbose', action='count', help='enable verbose output, repeat for more verbosity')
    parser.add_argument('-o', '--output', action='store', default='results', help='output directory for the results')
    parser.add_argument('--disable-sanity-checks', action='store_true', default=False, help='Disable sanity checks that would otherwise prevent the scans from running.')
    parser.error = lambda s: fail(s[0].upper() + s[1:])
    args = parser.parse_args()

    errors = False

    if args.concurrent_targets <= 0:
        error('Argument -ch/--concurrent-targets: must be greater or equal to 1.')
        errors = True

    concurrent_scans = args.concurrent_scans

    if concurrent_scans <= 0:
        error('Argument -ct/--concurrent-scans: must be greater or equal to 1.')
        errors = True

    port_scan_profile = args.profile
    if not valid_scan_profile(port_scan_profile, port_scan_profiles_config):
        errors = True

    outdir = args.output
    srvname = ''
    verbose = args.verbose if args.verbose is not None else 0

    if len(args.targets) == 0:
        error('You must specify at least one target to scan!')
        errors = True

    targets = []

    for target in args.targets:
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
                except:
                    error(target + ' does not appear to be a valid IP address, IP range, or resolvable hostname.')
                    errors = True

    if not args.disable_sanity_checks and len(targets) > 256:
        error('A total of ' + str(len(targets)) + ' targets would be scanned. If this is correct, re-run with the --disable-sanity-checks option to suppress this check.')
        errors = True

    if errors:
        sys.exit(1)

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
