import asyncio, inspect, os
from typing import final
from autorecon.config import config
from autorecon.io import e, info, warn, error

class Target:

	def __init__(self, address, ip, ipversion, type, autorecon):
		self.address = address
		self.ip = ip
		self.ipversion = ipversion
		self.type = type
		self.autorecon = autorecon
		self.basedir = ''
		self.reportdir = ''
		self.scandir = ''
		self.lock = asyncio.Lock()
		self.ports = None
		self.pending_services = []
		self.services = []
		self.scans = {'ports':{}, 'services':{}}
		self.running_tasks = {}

	async def add_service(self, service):
		async with self.lock:
			self.pending_services.append(service)

	def extract_service(self, line, regex=None):
		return self.autorecon.extract_service(line, regex)

	async def extract_services(self, stream, regex=None):
		return await self.autorecon.extract_services(stream, regex)

	@final
	def info(self, msg, verbosity=0):
		plugin = inspect.currentframe().f_back.f_locals['self']
		info('{bright}[{yellow}' + self.address + '{crst}/{bgreen}' + plugin.slug + '{crst}]{rst} ' + msg)

	@final
	def warn(self, msg, verbosity=0):
		plugin = inspect.currentframe().f_back.f_locals['self']
		warn('{bright}[{yellow}' + self.address + '{crst}/{bgreen}' + plugin.slug + '{crst}]{rst} ' + msg)

	@final
	def error(self, msg, verbosity=0):
		plugin = inspect.currentframe().f_back.f_locals['self']
		error('{bright}[{yellow}' + self.address + '{crst}/{bgreen}' + plugin.slug + '{crst}]{rst} ' + msg)

	async def execute(self, cmd, blocking=True, outfile=None, errfile=None, future_outfile=None):
		target = self

		# Create variables for command references.
		address = target.address
		addressv6 = target.address
		ipaddress = target.ip
		ipaddressv6 = target.ip
		scandir = target.scandir

		nmap_extra = target.autorecon.args.nmap
		if target.autorecon.args.nmap_append:
			nmap_extra += ' ' + target.autorecon.args.nmap_append

		if target.ipversion == 'IPv6':
			nmap_extra += ' -6'
			if addressv6 == target.ip:
				addressv6 = '[' + addressv6 + ']'
			ipaddressv6 = '[' + ipaddressv6 + ']'

		plugin = inspect.currentframe().f_back.f_locals['self']

		if config['proxychains']:
			nmap_extra += ' -sT'

		cmd = e(cmd)
		tag = plugin.slug

		info('Port scan {bblue}' + plugin.name + ' {green}(' + tag + '){rst} is running the following command against {byellow}' + address + '{rst}: ' + cmd, verbosity=2)

		if outfile is not None:
			outfile = os.path.join(target.scandir, e(outfile))

		if errfile is not None:
			errfile = os.path.join(target.scandir, e(errfile))

		if future_outfile is not None:
			future_outfile = os.path.join(target.scandir, e(future_outfile))

		target.scans['ports'][tag]['commands'].append([cmd, outfile if outfile is not None else future_outfile, errfile])

		async with target.lock:
			with open(os.path.join(target.scandir, '_commands.log'), 'a') as file:
				file.writelines(cmd + '\n\n')

		process, stdout, stderr = await target.autorecon.execute(cmd, target, tag, patterns=plugin.patterns, outfile=outfile, errfile=errfile)

		target.running_tasks[tag]['processes'].append({'process': process, 'stderr': stderr, 'cmd': cmd})

		# If process should block, sleep until stdout and stderr have finished.
		if blocking:
			while (not (stdout.ended and stderr.ended)):
				await asyncio.sleep(0.1)
			await process.wait()

		return process, stdout, stderr

class Service:

	def __init__(self, protocol, port, name, secure=False):
		self.target = None
		self.protocol = protocol.lower()
		self.port = int(port)
		self.name = name
		self.secure = secure
		self.manual_commands = {}

	@final
	def tag(self):
		return self.protocol + '/' + str(self.port) + '/' + self.name

	@final
	def full_tag(self):
		return self.protocol + '/' + str(self.port) + '/' + self.name + '/' + ('secure' if self.secure else 'insecure')

	@final
	def add_manual_commands(self, description, commands):
		if not isinstance(commands, list):
			commands = [commands]
		if description not in self.manual_commands:
			self.manual_commands[description] = []

		# Merge in new unique commands, while preserving order.
		[self.manual_commands[description].append(m) for m in commands if m not in self.manual_commands[description]]

	@final
	def add_manual_command(self, description, command):
		self.add_manual_commands(description, command)

	@final
	def info(self, msg):
		plugin = inspect.currentframe().f_back.f_locals['self']
		info('{bright}[{yellow}' + self.target.address + '{crst}/{bgreen}' + self.tag() + '/' + plugin.slug + '{crst}]{rst} ' + msg)

	@final
	def warn(self, msg):
		plugin = inspect.currentframe().f_back.f_locals['self']
		warn('{bright}[{yellow}' + self.target.address + '{crst}/{bgreen}' + self.tag() + '/' + plugin.slug + '{crst}]{rst} ' + msg)

	@final
	def error(self, msg):
		plugin = inspect.currentframe().f_back.f_locals['self']
		error('{bright}[{yellow}' + self.target.address + '{crst}/{bgreen}' + self.tag() + '/' + plugin.slug + '{crst}]{rst} ' + msg)

	@final
	async def execute(self, cmd, blocking=True, outfile=None, errfile=None, future_outfile=None):
		target = self.target

		# Create variables for command references.
		address = target.address
		addressv6 = target.address
		ipaddress = target.ip
		ipaddressv6 = target.ip
		scandir = target.scandir
		protocol = self.protocol
		port = self.port
		name = self.name

		if not config['no_port_dirs']:
			scandir = os.path.join(scandir, protocol + str(port))
			os.makedirs(scandir, exist_ok=True)
			os.makedirs(os.path.join(scandir, 'xml'), exist_ok=True)

		# Special cases for HTTP.
		http_scheme = 'https' if 'https' in self.name or self.secure is True else 'http'

		nmap_extra = target.autorecon.args.nmap
		if target.autorecon.args.nmap_append:
			nmap_extra += ' ' + target.autorecon.args.nmap_append

		if protocol == 'udp':
			nmap_extra += ' -sU'

		if target.ipversion == 'IPv6':
			nmap_extra += ' -6'
			if addressv6 == target.ip:
				addressv6 = '[' + addressv6 + ']'
			ipaddressv6 = '[' + ipaddressv6 + ']'

		if config['proxychains'] and protocol == 'tcp':
			nmap_extra += ' -sT'

		plugin = inspect.currentframe().f_back.f_locals['self']
		cmd = e(cmd)
		tag = self.tag() + '/' + plugin.slug
		plugin_tag = tag
		if plugin.run_once_boolean:
			plugin_tag = plugin.slug

		info('Service scan {bblue}' + plugin.name + ' {green}(' + tag + '){rst} is running the following command against {byellow}' + address + '{rst}: ' + cmd, verbosity=2)

		if outfile is not None:
			outfile = os.path.join(scandir, e(outfile))

		if errfile is not None:
			errfile = os.path.join(scandir, e(errfile))

		if future_outfile is not None:
			future_outfile = os.path.join(scandir, e(future_outfile))

		target.scans['services'][self][plugin_tag]['commands'].append([cmd, outfile if outfile is not None else future_outfile, errfile])

		async with target.lock:
			with open(os.path.join(target.scandir, '_commands.log'), 'a') as file:
				file.writelines(cmd + '\n\n')

		process, stdout, stderr = await target.autorecon.execute(cmd, target, tag, patterns=plugin.patterns, outfile=outfile, errfile=errfile)

		target.running_tasks[tag]['processes'].append({'process': process, 'stderr': stderr, 'cmd': cmd})

		# If process should block, sleep until stdout and stderr have finished.
		if blocking:
			while (not (stdout.ended and stderr.ended)):
				await asyncio.sleep(0.1)
			await process.wait()

		return process, stdout, stderr
