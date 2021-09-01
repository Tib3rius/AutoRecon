import asyncio, os, re, sys, signal, pkgutil, inspect, importlib, argparse, string, ipaddress, socket, time, math
from datetime import datetime
from typing import final
import traceback
import termios, tty
import select

try:
	import colorama, toml, unidecode
	from colorama import Fore, Style
except ModuleNotFoundError:
	print('One or more required modules was not installed. Please run or re-run: ' + ('sudo ' if os.getuid() == 0 else '') + 'python3 -m pip install -r requirements.txt')
	sys.exit(1)

colorama.init()

# Save current terminal settings so we can restore them.
terminal_settings = termios.tcgetattr(sys.stdin.fileno())

class Pattern:

	def __init__(self, pattern, description=None):
		self.pattern = pattern
		self.description = description

class Target:

	def __init__(self, address, ipversion, type, autorecon):
		self.address = address
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
		self.scans = []
		self.running_tasks = {}

	async def add_service(self, service):
		async with self.lock:
			self.pending_services.append(service)

	def extract_service(self, line, regex=None):
		return self.autorecon.extract_service(line, regex)

	async def extract_services(self, stream, regex=None):
		return await self.autorecon.extract_services(stream, regex)

	async def execute(self, cmd, blocking=True, outfile=None, errfile=None):
		target = self

		# Create variables for command references.
		address = target.address
		addressv6 = target.address
		scandir = target.scandir

		nmap_extra = self.autorecon.args.nmap
		if self.autorecon.args.nmap_append:
			nmap_extra += ' ' + self.autorecon.args.nmap_append

		if target.ipversion == 'IPv6':
			nmap_extra += ' -6'
			addressv6 = '[' + addressv6 + ']'

		plugin = inspect.currentframe().f_back.f_locals['self']

		cmd = e(cmd)

		tag = plugin.slug

		if target.autorecon.config['verbose'] >= 1:
			info('Port scan {bblue}' + plugin.name + ' (' + tag + '){rst} is running the following command against {byellow}' + address + '{rst}: ' + cmd)

		if outfile is not None:
			outfile = os.path.join(target.scandir, e(outfile))

		if errfile is not None:
			errfile = os.path.join(target.scandir, e(errfile))

		async with target.lock:
			with open(os.path.join(target.scandir, '_commands.log'), 'a') as file:
				file.writelines(cmd + '\n\n')

		process, stdout, stderr = await self.autorecon.execute(cmd, target, tag, patterns=plugin.patterns, outfile=outfile, errfile=errfile)

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
	async def execute(self, cmd, blocking=True, outfile=None, errfile=None):
		target = self.target

		# Create variables for command references.
		address = target.address
		addressv6 = target.address
		scandir = target.scandir
		protocol = self.protocol
		port = self.port
		name = self.name

		if target.autorecon.config['create_port_dirs']:
			scandir = os.path.join(scandir, protocol + str(port))
			os.makedirs(scandir, exist_ok=True)
			os.makedirs(os.path.join(scandir, 'xml'), exist_ok=True)

		# Special cases for HTTP.
		http_scheme = 'https' if 'https' in self.name or self.secure is True else 'http'

		nmap_extra = self.target.autorecon.args.nmap
		if self.target.autorecon.args.nmap_append:
			nmap_extra += ' ' + self.target.autorecon.args.nmap_append

		if protocol == 'udp':
			nmap_extra += ' -sU'

		if self.target.ipversion == 'IPv6':
			nmap_extra += ' -6'
			addressv6 = '[' + addressv6 + ']'

		plugin = inspect.currentframe().f_back.f_locals['self']

		cmd = e(cmd)

		tag = self.tag() + '/' + plugin.slug

		if target.autorecon.config['verbose'] >= 1:
			info('Service scan {bblue}' + plugin.name + ' (' + tag + '){rst} is running the following command against {byellow}' + address + '{rst}: ' + cmd)

		if outfile is not None:
			outfile = os.path.join(scandir, e(outfile))

		if errfile is not None:
			errfile = os.path.join(scandir, e(errfile))

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

class CommandStreamReader(object):

	def __init__(self, stream, target, tag, patterns=None, outfile=None):
		self.stream = stream
		self.target = target
		self.tag = tag
		self.lines = []
		self.patterns = patterns or []
		self.outfile = outfile
		self.ended = False

	# Read lines from the stream until it ends.
	async def _read(self):
		while True:
			if self.stream.at_eof():
				break
			try:
				line = (await self.stream.readline()).decode('utf8').rstrip()
			except ValueError:
				error('{bblue}[' + self.target.address + '/' + self.tag + ']{crst} A line was longer than 64 KiB and cannot be processed. Ignoring.')
				continue

			if self.target.autorecon.config['verbose'] >= 2:
				if line != '':
					info('{bblue}[' + self.target.address + '/' + self.tag + ']{crst} ' + line.replace('{', '{{').replace('}', '}}'))

			# Check lines for pattern matches.
			for p in self.patterns:
				matches = p.pattern.findall(line)
				for match in matches:
					async with self.target.lock:
						with open(os.path.join(self.target.scandir, '_patterns.log'), 'a') as file:
							if p.description:
								if self.target.autorecon.config['verbose'] >= 1:
									info('{bblue}[' + self.target.address + '/' + self.tag + ']{crst} {bmagenta}' + p.description.replace('{match}', '{bblue}' + match + '{crst}{bmagenta}') + '{rst}')
								file.writelines(p.description.replace('{match}', match) + '\n\n')
							else:
								if self.target.autorecon.config['verbose'] >= 1:
									info('{bblue}[' + self.target.address + '/' + self.tag + ']{crst} {bmagenta}Matched Pattern: {bblue}' + match + '{rst}')
								file.writelines('Matched Pattern: ' + match + '\n\n')

			if self.outfile is not None:
				with open(self.outfile, 'a') as writer:
					writer.write(line + '\n')
			self.lines.append(line)
		self.ended = True

	# Read a line from the stream cache.
	async def readline(self):
		while True:
			try:
				return self.lines.pop(0)
			except IndexError:
				if self.ended:
					return None
				else:
					await asyncio.sleep(0.1)

	# Read all lines from the stream cache.
	async def readlines(self):
		lines = []
		while True:
			line = await self.readline()
			if line is not None:
				lines.append(line)
			else:
				break
		return lines

class Plugin(object):

	def __init__(self):
		self.name = None
		self.slug = None
		self.description = None
		self.tags = ['default']
		self.priority = 1
		self.patterns = []
		self.autorecon = None
		self.disabled = False

	@final
	def add_option(self, name, default=None, help=None):
		self.autorecon.add_argument(self, name, metavar='VALUE', default=default, help=help)

	@final
	def add_constant_option(self, name, const, default=None, help=None):
		self.autorecon.add_argument(self, name, action='store_const', const=const, default=default, help=help)

	@final
	def add_true_option(self, name, help=None):
		self.autorecon.add_argument(self, name, action='store_true', help=help)

	@final
	def add_false_option(self, name, help=None):
		self.autorecon.add_argument(self, name, action='store_false', help=help)

	@final
	def add_list_option(self, name, default=None, help=None):
		self.autorecon.add_argument(self, name, nargs='+', metavar='VALUE', default=default, help=help)

	@final
	def add_choice_option(self, name, choices, default=None, help=None):
		if not isinstance(choices, list):
			fail('The choices argument for ' + self.name + '\'s ' + name + ' choice option should be a list.')
		self.autorecon.add_argument(self, name, choices=choices, default=default, help=help)

	@final
	def get_option(self, name):
		# TODO: make sure name is simple.
		name = self.slug.replace('-', '_') + '.' + slugify(name).replace('-', '_')

		if name in vars(self.autorecon.args):
			return vars(self.autorecon.args)[name]
		else:
			return None

	@final
	def get_global_option(self, name, default=None):
		name = 'global.' + slugify(name).replace('-', '_')

		if name in vars(self.autorecon.args):
			if vars(self.autorecon.args)[name] is None:
				if default:
					return default
				else:
					return None
			else:
				return vars(self.autorecon.args)[name]
		else:
			if default:
				return default
			return None

	@final
	def get_global(self, name, default=None):
		return self.get_global_option(name, default)

	@final
	def add_pattern(self, pattern, description=None):
		try:
			compiled = re.compile(pattern)
			if description:
				self.patterns.append(Pattern(compiled, description=description))
			else:
				self.patterns.append(Pattern(compiled))
		except re.error:
			fail('Error: The pattern "' + pattern + '" in the plugin "' + self.name + '" is invalid regex.')

class PortScan(Plugin):

	def __init__(self):
		super().__init__()
		self.type = None

	async def run(self, target):
		raise NotImplementedError

class ServiceScan(Plugin):

	def __init__(self):
		super().__init__()
		self.ports = {'tcp':[], 'udp':[]}
		self.ignore_ports = {'tcp':[], 'udp':[]}
		self.services = []
		self.service_names = []
		self.ignore_service_names = []
		self.match_all_service_names_boolean = False
		self.run_once_boolean = False
		self.require_ssl_boolean = False

	@final
	def match_service(self, protocol, port, name, negative_match=False):
		protocol = protocol.lower()
		if protocol not in ['tcp', 'udp']:
			print('Invalid protocol.')
			sys.exit(1)

		if not isinstance(port, list):
			port = [port]

		port = list(map(int, port))

		if not isinstance(name, list):
			name = [name]

		valid_regex = True
		for r in name:
			try:
				re.compile(r)
			except re.error:
				print('Invalid regex: ' + r)
				valid_regex = False

		if not valid_regex:
			sys.exit(1)

		service = {'protocol': protocol, 'port': port, 'name': name, 'negative_match': negative_match}
		self.services.append(service)

	@final
	def match_port(self, protocol, port, negative_match=False):
		protocol = protocol.lower()
		if protocol not in ['tcp', 'udp']:
			print('Invalid protocol.')
			sys.exit(1)
		else:
			if not isinstance(port, list):
				port = [port]

			port = list(map(int, port))

			if negative_match:
				self.ignore_ports[protocol] = list(set(self.ignore_ports[protocol] + port))
			else:
				self.ports[protocol] = list(set(self.ports[protocol] + port))

	@final
	def match_service_name(self, name, negative_match=False):
		if not isinstance(name, list):
			name = [name]

		valid_regex = True
		for r in name:
			try:
				re.compile(r)
			except re.error:
				print('Invalid regex: ' + r)
				valid_regex = False

		if valid_regex:
			if negative_match:
				self.ignore_service_names = list(set(self.ignore_service_names + name))
			else:
				self.service_names = list(set(self.service_names + name))
		else:
			sys.exit(1)

	@final
	def require_ssl(self, boolean):
		self.require_ssl_boolean = boolean

	@final
	def run_once(self, boolean):
		self.run_once_boolean = boolean

	@final
	def match_all_service_names(self, boolean):
		self.match_all_service_names_boolean = boolean

class AutoRecon(object):

	def __init__(self):
		self.pending_targets = []
		self.scanning_targets = []
		self.plugins = {}
		self.__slug_regex = re.compile('^[a-z0-9\-]+$')
		self.plugin_types = {'port':[], 'service':[]}
		self.port_scan_semaphore = None
		self.service_scan_semaphore = None
		self.argparse = None
		self.argparse_group = None
		self.args = None
		self.missing_services = []
		self.taglist = []
		self.tags = []
		self.excluded_tags = []
		self.patterns = []
		self.configurable_keys = [
			'ports',
			'max_scans',
			'max_port_scans',
			'tags',
			'exclude_tags',
			'plugins_dir',
			'add_plugins-dir',
			'outdir',
			'single_target',
			'only_scans_dir',
			'create_port_dirs',
			'heartbeat',
			'timeout',
			'target_timeout',
			'nmap',
			'nmap_append',
			'disable_sanity_checks',
			'disable_keyboard_control',
			'force_services',
			'accessible',
			'verbose'
		]
		self.configurable_boolean_keys = ['single_target', 'only_scans_dir', 'create_port_dirs', 'disable_sanity_checks', 'accessible']
		self.config = {
			'protected_classes': ['autorecon', 'target', 'service', 'commandstreamreader', 'plugin', 'portscan', 'servicescan', 'global', 'pattern'],
			'global_file': os.path.dirname(os.path.realpath(__file__)) + '/global.toml',
			'ports': None,
			'max_scans': 50,
			'max_port_scans': None,
			'tags': 'default',
			'exclude_tags': None,
			'plugins_dir': os.path.dirname(os.path.abspath(__file__)) + '/plugins',
			'add_plugins_dir': None,
			'outdir': 'results',
			'single_target': False,
			'only_scans_dir': False,
			'create_port_dirs': False,
			'heartbeat': 60,
			'timeout': None,
			'target_timeout': None,
			'nmap': '-vv --reason -Pn',
			'nmap_append': '',
			'disable_sanity_checks': False,
			'disable_keyboard_control': False,
			'force_services': None,
			'accessible': False,
			'verbose': 0
		}
		self.errors = False
		self.lock = asyncio.Lock()
		self.load_slug = None
		self.load_module = None

	def add_argument(self, plugin, name, **kwargs):
		# TODO: make sure name is simple.
		name = '--' + plugin.slug + '.' + slugify(name)

		if self.argparse_group is None:
			self.argparse_group = self.argparse.add_argument_group('plugin arguments', description='These are optional arguments for certain plugins.')
		self.argparse_group.add_argument(name, **kwargs)

	def extract_service(self, line, regex):
		if regex is None:
			regex = '^(?P<port>\d+)\/(?P<protocol>(tcp|udp))(.*)open(\s*)(?P<service>[\w\-\/]+)(\s*)(.*)$'
		match = re.search(regex, line)
		if match:
			protocol = match.group('protocol').lower()
			port = int(match.group('port'))
			service = match.group('service')
			secure = True if 'ssl' in service or 'tls' in service else False

			if service.startswith('ssl/') or service.startswith('tls/'):
				service = service[4:]

			from autorecon import Service
			return Service(protocol, port, service, secure)
		else:
			return None

	async def extract_services(self, stream, regex):
		if not isinstance(stream, CommandStreamReader):
			print('Error: extract_services must be passed an instance of a CommandStreamReader.')
			sys.exit(1)

		services = []
		while True:
			line = await stream.readline()
			if line is not None:
				service = self.extract_service(line, regex)
				if service:
					services.append(service)
			else:
				break
		return services

	def register(self, plugin, filename):
		if plugin.disabled:
			return

		for _, loaded_plugin in self.plugins.items():
			if plugin.name == loaded_plugin.name:
				fail('Error: Duplicate plugin name "' + plugin.name + '" detected in ' + filename + '.', file=sys.stderr)

		if plugin.slug is None:
			plugin.slug = slugify(plugin.name)
		elif not self.__slug_regex.match(plugin.slug):
			fail('Error: provided slug "' + plugin.slug + '" in ' + filename + ' is not valid (must only contain lowercase letters, numbers, and hyphens).', file=sys.stderr)

		if plugin.slug in self.config['protected_classes']:
			fail('Error: plugin slug "' + plugin.slug + '" in ' + filename + ' is a protected string. Please change.')

		if plugin.slug not in self.plugins:

			for _, loaded_plugin in self.plugins.items():
				if plugin is loaded_plugin:
					fail('Error: plugin "' + plugin.name + '" in ' + filename + ' already loaded as "' + loaded_plugin.name + '" (' + str(loaded_plugin) + ')', file=sys.stderr)

			configure_function_found = False
			run_coroutine_found = False
			manual_function_found = False

			for member_name, member_value in inspect.getmembers(plugin, predicate=inspect.ismethod):
				if member_name == 'configure':
					configure_function_found = True
				elif member_name == 'run' and inspect.iscoroutinefunction(member_value):
					if len(inspect.getfullargspec(member_value).args) != 2:
						fail('Error: the "run" coroutine in the plugin "' + plugin.name + '" in ' + filename + ' should have two arguments.', file=sys.stderr)
					run_coroutine_found = True
				elif member_name == 'manual':
					if len(inspect.getfullargspec(member_value).args) != 3:
						fail('Error: the "manual" function in the plugin "' + plugin.name + '" in ' + filename + ' should have three arguments.', file=sys.stderr)
					manual_function_found = True

			if not run_coroutine_found and not manual_function_found:
				fail('Error: the plugin "' + plugin.name + '" in ' + filename + ' needs either a "manual" function, a "run" coroutine, or both.', file=sys.stderr)

			from autorecon import PortScan, ServiceScan
			if issubclass(plugin.__class__, PortScan):
				self.plugin_types["port"].append(plugin)
			elif issubclass(plugin.__class__, ServiceScan):
				self.plugin_types["service"].append(plugin)
			else:
				fail('Plugin "' + plugin.name + '" in ' + filename + ' is neither a PortScan nor a ServiceScan.', file=sys.stderr)

			plugin.tags = [tag.lower() for tag in plugin.tags]

			# Add plugin tags to tag list.
			[autorecon.taglist.append(t) for t in plugin.tags if t not in autorecon.tags]

			plugin.autorecon = self
			if configure_function_found:
				plugin.configure()
			self.plugins[plugin.slug] = plugin
		else:
			fail('Error: plugin slug "' + plugin.slug + '" in ' + filename + ' is already assigned.', file=sys.stderr)

	async def execute(self, cmd, target, tag, patterns=None, outfile=None, errfile=None):
		if patterns:
			combined_patterns = self.patterns + patterns
		else:
			combined_patterns = self.patterns

		process = await asyncio.create_subprocess_shell(
			cmd,
			stdin=open('/dev/null'),
			stdout=asyncio.subprocess.PIPE,
			stderr=asyncio.subprocess.PIPE)

		cout = CommandStreamReader(process.stdout, target, tag, patterns=combined_patterns, outfile=outfile)
		cerr = CommandStreamReader(process.stderr, target, tag, patterns=combined_patterns, outfile=errfile)

		asyncio.create_task(cout._read())
		asyncio.create_task(cerr._read())

		return process, cout, cerr

# Since this file is run as the main method and also imported by plugins,
# we need to make sure that only one instance of the AutoRecon is
# created. This cannot be done with Singletons unfortunately, which is
# why this hack is here.
if 'autorecon' not in sys.modules: # If this file is not yet imported, create the AutoRecon object
	autorecon = AutoRecon()
else: # Otherwise, assign it from the __main__ module.
	autorecon = sys.modules['__main__'].autorecon

def e(*args, frame_index=1, **kvargs):
	frame = sys._getframe(frame_index)

	vals = {}

	vals.update(frame.f_globals)
	vals.update(frame.f_locals)
	vals.update(kvargs)

	return string.Formatter().vformat(' '.join(args), args, vals)

def fformat(s):
	return e(s, frame_index=3)

def cprint(*args, color=Fore.RESET, char='*', sep=' ', end='\n', frame_index=1, file=sys.stdout, printmsg=True, **kvargs):
	frame = sys._getframe(frame_index)

	vals = {
		'bgreen':  Fore.GREEN  + Style.BRIGHT,
		'bred':	Fore.RED	+ Style.BRIGHT,
		'bblue':   Fore.BLUE   + Style.BRIGHT,
		'byellow': Fore.YELLOW + Style.BRIGHT,
		'bmagenta': Fore.MAGENTA + Style.BRIGHT,

		'green':  Fore.GREEN,
		'red':	Fore.RED,
		'blue':   Fore.BLUE,
		'yellow': Fore.YELLOW,
		'magenta': Fore.MAGENTA,

		'bright': Style.BRIGHT,
		'srst':   Style.NORMAL,
		'crst':   Fore.RESET,
		'rst':	Style.NORMAL + Fore.RESET
	}

	if autorecon.config['accessible']:
		 vals = {'bgreen':'', 'bred':'', 'bblue':'', 'byellow':'', 'bmagenta':'', 'green':'', 'red':'', 'blue':'', 'yellow':'', 'magenta':'', 'bright':'', 'srst':'', 'crst':'', 'rst':''}

	vals.update(frame.f_globals)
	vals.update(frame.f_locals)
	vals.update(kvargs)

	unfmt = ''
	if char is not None and not autorecon.config['accessible']:
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

	if printmsg:
		print(fmted, sep=sep, end=end, file=file)
	else:
		return fmted

def debug(*args, color=Fore.GREEN, sep=' ', end='\n', file=sys.stdout, **kvargs):
	if verbose >= 2:
		if autorecon.config['accessible']:
			args = ('Debug:',) + args
		cprint(*args, color=color, char='-', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def info(*args, sep=' ', end='\n', file=sys.stdout, **kvargs):
	cprint(*args, color=Fore.BLUE, char='*', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def warn(*args, sep=' ', end='\n', file=sys.stderr,**kvargs):
	if autorecon.config['accessible']:
		args = ('Warning:',) + args
	cprint(*args, color=Fore.YELLOW, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def error(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
	if autorecon.config['accessible']:
		args = ('Error:',) + args
	cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)

def fail(*args, sep=' ', end='\n', file=sys.stderr, **kvargs):
	if autorecon.config['accessible']:
		args = ('Failure:',) + args
	cprint(*args, color=Fore.RED, char='!', sep=sep, end=end, file=file, frame_index=2, **kvargs)
	exit(-1)

def calculate_elapsed_time(start_time, short=False):
	elapsed_seconds = round(time.time() - start_time)

	m, s = divmod(elapsed_seconds, 60)
	h, m = divmod(m, 60)

	elapsed_time = []
	if short:
		elapsed_time.append(str(h).zfill(2))
	else:
		if h == 1:
			elapsed_time.append(str(h) + ' hour')
		elif h > 1:
			elapsed_time.append(str(h) + ' hours')

	if short:
		elapsed_time.append(str(m).zfill(2))
	else:
		if m == 1:
			elapsed_time.append(str(m) + ' minute')
		elif m > 1:
			elapsed_time.append(str(m) + ' minutes')

	if short:
		elapsed_time.append(str(s).zfill(2))
	else:
		if s == 1:
			elapsed_time.append(str(s) + ' second')
		elif s > 1:
			elapsed_time.append(str(s) + ' seconds')
		else:
			elapsed_time.append('less than a second')

	if short:
		return ':'.join(elapsed_time)
	else:
		return ', '.join(elapsed_time)

def slugify(name):
	return re.sub(r'[\W_]+', '-', unidecode.unidecode(name).lower()).strip('-')

def cancel_all_tasks(signal, frame):
	for task in asyncio.all_tasks():
		task.cancel()

	for target in autorecon.scanning_targets:
		for process_list in target.running_tasks.values():
			for process_dict in process_list['processes']:
				try:
					process_dict['process'].kill()
				except ProcessLookupError: # Will get raised if the process finishes before we get to killing it.
					pass

	if not autorecon.config['disable_keyboard_control']:
		# Restore original terminal settings.
		termios.tcsetattr(sys.stdin.fileno(), termios.TCSADRAIN, terminal_settings)

def timeout(signal, frame):
	raise Exception("Function timed out.")

async def start_heartbeat(target, period=60):
	while True:
		await asyncio.sleep(period)
		async with target.lock:
			count = len(target.running_tasks)

			tasks_list = ''
			if target.autorecon.config['verbose'] >= 1:
				tasks_list = ': {bblue}' + ', '.join(target.running_tasks.keys()) + '{rst}'

			current_time = datetime.now().strftime('%H:%M:%S')

			if count > 1:
				info('{bgreen}' + current_time + '{rst} - There are {byellow}' + str(count) + '{rst} scans still running against {byellow}' + target.address + '{rst}' + tasks_list)
			elif count == 1:
				info('{bgreen}' + current_time + '{rst} - There is {byellow}1{rst} scan still running against {byellow}' + target.address + '{rst}' + tasks_list)

async def keyboard():
	input = ''
	while True:
		if select.select([sys.stdin],[],[],0.1)[0]:
			input += sys.stdin.buffer.read1(-1).decode('utf8')
			while input != '':
				if len(input) >= 3:
					if input[:3] == '\x1b[A':
						input = ''
						if autorecon.config['verbose'] == 2:
							info('Verbosity is already at the highest level.')
						else:
							autorecon.config['verbose'] += 1
							info('Verbosity increased to ' + str(autorecon.config['verbose']))
					elif input[:3] == '\x1b[B':
						input = ''
						if autorecon.config['verbose'] == 0:
							info('Verbosity is already at the lowest level.')
						else:
							autorecon.config['verbose'] -= 1
							info('Verbosity decreased to ' + str(autorecon.config['verbose']))
					else:
						if input[0] != 's':
							input = input[1:]

				if len(input) > 0 and input[0] == 's':
					input = input[1:]
					for target in autorecon.scanning_targets:
						count = len(target.running_tasks)

						tasks_list = []
						if target.autorecon.config['verbose'] >= 1:
							for key, value in target.running_tasks.items():
								elapsed_time = calculate_elapsed_time(value['start'], short=True)
								tasks_list.append('{bblue}' + key + '{rst}' + ' (elapsed: ' + elapsed_time + ')')

							tasks_list = ':\n    ' + '\n    '.join(tasks_list)
						else:
							tasks_list = ''

						current_time = datetime.now().strftime('%H:%M:%S')

						if count > 1:
							info('{bgreen}' + current_time + '{rst} - There are {byellow}' + str(count) + '{rst} scans still running against {byellow}' + target.address + '{rst}' + tasks_list)
						elif count == 1:
							info('{bgreen}' + current_time + '{rst} - There is {byellow}1{rst} scan still running against {byellow}' + target.address + '{rst}' + tasks_list)
				else:
					input = input[1:]
		await asyncio.sleep(0.1)

async def port_scan(plugin, target):
	if autorecon.config['ports']:
		if autorecon.config['ports']['tcp'] or autorecon.config['ports']['udp']:
			target.ports = {'tcp':None, 'udp':None}
			if autorecon.config['ports']['tcp']:
				target.ports['tcp'] = ','.join(autorecon.config['ports']['tcp'])
			if autorecon.config['ports']['udp']:
				target.ports['udp'] = ','.join(autorecon.config['ports']['udp'])
			if plugin.type is None:
				warn('Port scan {bblue}' + plugin.name + ' (' + plugin.slug + '){rst} does not have a type set, and --ports was used. Skipping.')
				return {'type':'port', 'plugin':plugin, 'result':[]}
			else:
				if plugin.type == 'tcp' and not autorecon.config['ports']['tcp']:
					warn('Port scan {bblue}' + plugin.name + ' (' + plugin.slug + '){rst} is a TCP port scan but no TCP ports were set using --ports. Skipping')
					return {'type':'port', 'plugin':plugin, 'result':[]}
				elif plugin.type == 'udp' and not autorecon.config['ports']['udp']:
					warn('Port scan {bblue}' + plugin.name + ' (' + plugin.slug + '){rst} is a UDP port scan but no UDP ports were set using --ports. Skipping')
					return {'type':'port', 'plugin':plugin, 'result':[]}

	async with target.autorecon.port_scan_semaphore:
		info('Port scan {bblue}' + plugin.name + ' (' + plugin.slug + '){rst} running against {byellow}' + target.address + '{rst}')

		start_time = time.time()

		async with target.lock:
			target.running_tasks[plugin.slug] = {'plugin': plugin, 'processes': [], 'start': start_time}

		try:
			result = await plugin.run(target)
		except Exception as ex:
			exc_type, exc_value, exc_tb = sys.exc_info()
			error_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb)[-2:])
			raise Exception(cprint('Error: Port scan {bblue}' + plugin.name + ' (' + plugin.slug + '){rst} running against {byellow}' + target.address + '{rst} produced an exception:\n\n' + error_text, color=Fore.RED, char='!', printmsg=False))

		for process_dict in target.running_tasks[plugin.slug]['processes']:
			if process_dict['process'].returncode is None:
				warn('A process was left running after port scan {bblue}' + plugin.name + ' (' + plugin.slug + '){rst} against {byellow}' + target.address + '{rst} finished. Please ensure non-blocking processes are awaited before the run coroutine finishes. Awaiting now.')
				await process_dict['process'].wait()

			if process_dict['process'].returncode != 0:
				errors = []
				while True:
					line = await process_dict['stderr'].readline()
					if line is not None:
						errors.append(line + '\n')
					else:
						break
				error('Port scan {bblue}' + plugin.name + ' (' + plugin.slug + '){rst} ran a command against {byellow}' + target.address + '{rst} which returned a non-zero exit code (' + str(process_dict['process'].returncode) + '). Check ' + target.scandir + '/_errors.log for more details.')
				async with target.lock:
					with open(os.path.join(target.scandir, '_errors.log'), 'a') as file:
						file.writelines('[*] Port scan ' + plugin.name + ' (' + plugin.slug + ') ran a command which returned a non-zero exit code (' + str(process_dict['process'].returncode) + ').\n')
						file.writelines('[-] Command: ' + process_dict['cmd'] + '\n')
						if errors:
							file.writelines(['[-] Error Output:\n'] + errors + ['\n'])
						else:
							file.writelines('\n')

		elapsed_time = calculate_elapsed_time(start_time)

		async with target.lock:
			target.running_tasks.pop(plugin.slug, None)

		info('Port scan {bblue}' + plugin.name + ' (' + plugin.slug + '){rst} against {byellow}' + target.address + '{rst} finished in ' + elapsed_time)
		return {'type':'port', 'plugin':plugin, 'result':result}

async def service_scan(plugin, service):
	from autorecon import PortScan
	semaphore = service.target.autorecon.service_scan_semaphore

	if not service.target.autorecon.config['force_services']:
		# If service scan semaphore is locked, see if we can use port scan semaphore.
		while True:
			if semaphore.locked():
				if semaphore != service.target.autorecon.port_scan_semaphore: # This will be true unless user sets max_scans == max_port_scans

					port_scan_task_count = 0
					for targ in service.target.autorecon.scanning_targets:
						for process_list in targ.running_tasks.values():
							if issubclass(process_list['plugin'].__class__, PortScan):
								port_scan_task_count += 1

					if not service.target.autorecon.pending_targets and (service.target.autorecon.config['max_port_scans'] - port_scan_task_count) >= 1: # If no more targets, and we have room, use port scan semaphore.
						if service.target.autorecon.port_scan_semaphore.locked():
							await asyncio.sleep(1)
							continue
						semaphore = service.target.autorecon.port_scan_semaphore
						break
					else: # Do some math to see if we can use the port scan semaphore.
						if (service.target.autorecon.config['max_port_scans'] - (port_scan_task_count + (len(service.target.autorecon.pending_targets) * service.target.autorecon.config['port_scan_plugin_count']))) >= 1:
							if service.target.autorecon.port_scan_semaphore.locked():
								await asyncio.sleep(1)
								continue
							semaphore = service.target.autorecon.port_scan_semaphore
							break
						else:
							await asyncio.sleep(1)
				else:
					break
			else:
				break

	async with semaphore:
		# Create variables for fformat references.
		address = service.target.address
		addressv6 = service.target.address
		scandir = service.target.scandir
		protocol = service.protocol
		port = service.port
		name = service.name

		# Special cases for HTTP.
		http_scheme = 'https' if 'https' in service.name or service.secure is True else 'http'

		nmap_extra = service.target.autorecon.args.nmap
		if service.target.autorecon.args.nmap_append:
			nmap_extra += ' ' + service.target.autorecon.args.nmap_append

		if protocol == 'udp':
			nmap_extra += ' -sU'

		if service.target.ipversion == 'IPv6':
			nmap_extra += ' -6'
			addressv6 = '[' + addressv6 + ']'

		tag = service.tag() + '/' + plugin.slug

		info('Service scan {bblue}' + plugin.name + ' (' + tag + '){rst} running against {byellow}' + service.target.address + '{rst}')

		start_time = time.time()

		async with service.target.lock:
			service.target.running_tasks[tag] = {'plugin': plugin, 'processes': [], 'start': start_time}

		try:
			result = await plugin.run(service)
		except Exception as ex:
			exc_type, exc_value, exc_tb = sys.exc_info()
			error_text = ''.join(traceback.format_exception(exc_type, exc_value, exc_tb)[-2:])
			raise Exception(cprint('Error: Service scan {bblue}' + plugin.name + ' (' + tag + '){rst} running against {byellow}' + service.target.address + '{rst} produced an exception:\n\n' + error_text, color=Fore.RED, char='!', printmsg=False))

		for process_dict in service.target.running_tasks[tag]['processes']:
			if process_dict['process'].returncode is None:
				warn('A process was left running after service scan {bblue}' + plugin.name + ' (' + tag + '){rst} against {byellow}' + service.target.address + '{rst} finished. Please ensure non-blocking processes are awaited before the run coroutine finishes. Awaiting now.')
				await process_dict['process'].wait()

			if process_dict['process'].returncode != 0:
				errors = []
				while True:
					line = await process_dict['stderr'].readline()
					if line is not None:
						errors.append(line + '\n')
					else:
						break
				error('Service scan {bblue}' + plugin.name + ' (' + tag + '){rst} ran a command against {byellow}' + service.target.address + '{rst} which returned a non-zero exit code (' + str(process_dict['process'].returncode) + '). Check ' + service.target.scandir + '/_errors.log for more details.')
				async with service.target.lock:
					with open(os.path.join(service.target.scandir, '_errors.log'), 'a') as file:
						file.writelines('[*] Service scan ' + plugin.name + ' (' + tag + ') ran a command which returned a non-zero exit code (' + str(process_dict['process'].returncode) + ').\n')
						file.writelines('[-] Command: ' + process_dict['cmd'] + '\n')
						if errors:
							file.writelines(['[-] Error Output:\n'] + errors + ['\n'])
						else:
							file.writelines('\n')

		elapsed_time = calculate_elapsed_time(start_time)

		async with service.target.lock:
			service.target.running_tasks.pop(tag, None)

		info('Service scan {bblue}' + plugin.name + ' (' + tag + '){rst} against {byellow}' + service.target.address + '{rst} finished in ' + elapsed_time)
		return {'type':'service', 'plugin':plugin, 'result':result}

async def scan_target(target):
	if target.autorecon.config['single_target']:
		basedir = os.path.abspath(target.autorecon.config['outdir'])
	else:
		basedir = os.path.abspath(os.path.join(target.autorecon.config['outdir'], target.address))
	target.basedir = basedir
	os.makedirs(basedir, exist_ok=True)

	if not target.autorecon.config['only_scans_dir']:
		exploitdir = os.path.join(basedir, 'exploit')
		os.makedirs(exploitdir, exist_ok=True)

		lootdir = os.path.join(basedir, 'loot')
		os.makedirs(lootdir, exist_ok=True)

		reportdir = os.path.join(basedir, 'report')
		target.reportdir = reportdir
		os.makedirs(reportdir, exist_ok=True)

		open(os.path.join(reportdir, 'local.txt'), 'a').close()
		open(os.path.join(reportdir, 'proof.txt'), 'a').close()

		screenshotdir = os.path.join(reportdir, 'screenshots')
		os.makedirs(screenshotdir, exist_ok=True)

	scandir = os.path.join(basedir, 'scans')
	target.scandir = scandir
	os.makedirs(scandir, exist_ok=True)

	os.makedirs(os.path.join(scandir, 'xml'), exist_ok=True)

	pending = []

	heartbeat = asyncio.create_task(start_heartbeat(target, period=target.autorecon.config['heartbeat']))

	services = []
	if autorecon.config['force_services']:
		forced_services = [x.strip().lower() for x in autorecon.config['force_services']]

		for forced_service in forced_services:
			match = re.search('(?P<protocol>(tcp|udp))\/(?P<port>\d+)\/(?P<service>[\w\-\/]+)\/(?P<secure>secure|insecure)', forced_service)
			if match:
				protocol = match.group('protocol')
				port = int(match.group('port'))
				service = match.group('service')
				secure = True if match.group('secure') == 'secure' else False
				service = Service(protocol, port, service, secure)
				service.target = target
				services.append(service)

		if services:
			pending.append(asyncio.create_task(asyncio.sleep(0)))
		else:
			error('No services were defined. Please check your service syntax: [tcp|udp]/<port>/<service-name>/[secure|insecure]')
			heartbeat.cancel()
			keyboard_monitor.cancel()
			autorecon.errors = True
			return
	else:
		for plugin in target.autorecon.plugin_types['port']:
			plugin_tag_set = set(plugin.tags)

			matching_tags = False
			for tag_group in target.autorecon.tags:
				if set(tag_group).issubset(plugin_tag_set):
					matching_tags = True
					break

			excluded_tags = False
			for tag_group in target.autorecon.excluded_tags:
				if set(tag_group).issubset(plugin_tag_set):
					excluded_tags = True
					break

			if matching_tags and not excluded_tags:
				pending.append(asyncio.create_task(port_scan(plugin, target)))

	async with autorecon.lock:
		autorecon.scanning_targets.append(target)

	start_time = time.time()
	info('Scanning target {byellow}' + target.address + '{rst}')

	timed_out = False
	while pending:
		done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED, timeout=1)

		# Check if global timeout has occurred.
		if autorecon.config['target_timeout'] is not None:
			elapsed_seconds = round(time.time() - start_time)
			m, s = divmod(elapsed_seconds, 60)
			if m >= autorecon.config['target_timeout']:
				timed_out = True
				break

		if not autorecon.config['force_services']:
			# Extract Services
			services = []

			async with target.lock:
				while target.pending_services:
					services.append(target.pending_services.pop(0))

			for task in done:
				try:
					if task.exception():
						print(task.exception())
						continue
				except asyncio.InvalidStateError:
					pass

				if task.result()['type'] == 'port':
					for service in (task.result()['result'] or []):
						services.append(service)

		for service in services:
			if service.full_tag() not in target.services:
				target.services.append(service.full_tag())
			else:
				continue

			info('Found {bmagenta}' + service.name + '{rst} on {bmagenta}' + service.protocol + '/' + str(service.port) + '{rst} on {byellow}' + target.address + '{rst}')

			if not autorecon.config['only_scans_dir']:
				with open(os.path.join(target.reportdir, 'notes.txt'), 'a') as file:
					file.writelines('[*] ' + service.name + ' found on ' + service.protocol + '/' + str(service.port) + '.\n\n\n\n')

			service.target = target

			# Create variables for command references.
			address = target.address
			addressv6 = target.address
			scandir = target.scandir
			protocol = service.protocol
			port = service.port

			# Special cases for HTTP.
			http_scheme = 'https' if 'https' in service.name or service.secure is True else 'http'

			nmap_extra = target.autorecon.args.nmap
			if target.autorecon.args.nmap_append:
				nmap_extra += ' ' + target.autorecon.args.nmap_append

			if protocol == 'udp':
				nmap_extra += ' -sU'

			if target.ipversion == 'IPv6':
				nmap_extra += ' -6'
				addressv6 = '[' + addressv6 + ']'

			service_match = False
			matching_plugins = []
			heading = False

			for plugin in target.autorecon.plugin_types['service']:
				plugin_was_run = False
				plugin_service_match = False
				plugin_tag = service.tag() + '/' + plugin.slug

				for service_dict in plugin.services:
					if service_dict['protocol'] == protocol and port in service_dict['port']:
						for name in service_dict['name']:
							if service_dict['negative_match']:
								if name not in plugin.ignore_service_names:
									plugin.ignore_service_names.append(name)
							else:
								if name not in plugin.service_names:
									plugin.service_names.append(name)
					else:
						continue

				for s in plugin.service_names:
					if re.search(s, service.name):
						plugin_service_match = True

					if plugin.match_all_service_names_boolean or plugin_service_match:
						plugin_tag_set = set(plugin.tags)

						matching_tags = False
						for tag_group in target.autorecon.tags:
							if set(tag_group).issubset(plugin_tag_set):
								matching_tags = True
								break

						excluded_tags = False
						for tag_group in target.autorecon.excluded_tags:
							if set(tag_group).issubset(plugin_tag_set):
								excluded_tags = True
								break

						# TODO: Maybe make this less messy, keep manual-only plugins separate?
						plugin_is_runnable = False
						for member_name, _ in inspect.getmembers(plugin, predicate=inspect.ismethod):
							if member_name == 'run':
								plugin_is_runnable = True
								break

						if plugin_is_runnable and matching_tags and not excluded_tags:
							# Skip plugin if run_once_boolean and plugin already in target scans
							if plugin.run_once_boolean and (plugin.slug,) in target.scans:
								warn('{byellow}[' + plugin_tag + ' against ' + target.address + ']{srst} Plugin should only be run once and it appears to have already been queued. Skipping.{rst}')
								break

							# Skip plugin if require_ssl_boolean and port is not secure
							if plugin.require_ssl_boolean and not service.secure:
								plugin_service_match = False
								break

							# Skip plugin if service port is in ignore_ports:
							if port in plugin.ignore_ports[protocol]:
								plugin_service_match = False
								warn('{byellow}[' + plugin_tag + ' against ' + target.address + ']{srst} Plugin cannot be run against ' + protocol + ' port ' + str(port) + '. Skipping.{rst}')
								break

							# Skip plugin if plugin has required ports and service port is not in them:
							if plugin.ports[protocol] and port not in plugin.ports[protocol]:
								plugin_service_match = False
								warn('{byellow}[' + plugin_tag + ' against ' + target.address + ']{srst} Plugin can only run on specific ports. Skipping.{rst}')
								break

							for i in plugin.ignore_service_names:
								if re.search(i, service.name):
									warn('{byellow}[' + plugin_tag + ' against ' + target.address + ']{srst} Plugin cannot be run against this service. Skipping.{rst}')
									break

							# TODO: check if plugin matches tags, BUT run manual commands anyway!
							plugin_was_run = True
							matching_plugins.append(plugin)

						for member_name, _ in inspect.getmembers(plugin, predicate=inspect.ismethod):
							if member_name == 'manual':
								plugin.manual(service, plugin_was_run)

								if service.manual_commands and (not plugin.run_once_boolean or (plugin.run_once_boolean and (plugin.slug,) not in target.scans)):
									with open(os.path.join(scandir, '_manual_commands.txt'), 'a') as file:
										if not heading:
											file.write(e('[*] {service.name} on {service.protocol}/{service.port}\n\n'))
											heading = True
										for description, commands in service.manual_commands.items():
											file.write('\t[-] ' + e(description) + '\n\n')
											for command in commands:
												file.write('\t\t' + e(command) + '\n\n')
										file.flush()

								service.manual_commands = {}
								break

						break

				if plugin_service_match:
					service_match = True

			for plugin in matching_plugins:
				plugin_tag = service.tag() + '/' + plugin.slug

				scan_tuple = (service.protocol, service.port, service.name, plugin.slug)
				if plugin.run_once_boolean:
					scan_tuple = (plugin.slug,)

				if scan_tuple in target.scans:
					warn('{byellow}[' + plugin_tag + ' against ' + target.address + ']{srst} Plugin appears to have already been queued, but it is not marked as run_once. Possible duplicate service tag? Skipping.{rst}')
					continue
				else:
					target.scans.append(scan_tuple)

				pending.add(asyncio.create_task(service_scan(plugin, service)))

			if not service_match:
				warn('{byellow}[' + target.address + ']{srst} Service ' + service.full_tag() + ' did not match any plugins based on the service name.{rst}')
				if service.full_tag() not in target.autorecon.missing_services:
					target.autorecon.missing_services.append(service.full_tag())

	heartbeat.cancel()
	elapsed_time = calculate_elapsed_time(start_time)

	if timed_out:

		for task in pending:
			task.cancel()

		for process_list in target.running_tasks.values():
			for process_dict in process_list['processes']:
				process_dict['process'].kill()

		warn('{byellow}Scanning target ' + target.address + ' took longer than the specified target period (' + str(autorecon.config['target_timeout']) + ' min). Cancelling scans and moving to next target.{rst}')
	else:
		info('Finished scanning target {byellow}' + target.address + '{rst} in ' + elapsed_time)

	async with autorecon.lock:
		autorecon.scanning_targets.remove(target)

async def main():
	from autorecon import Plugin, PortScan, ServiceScan, Target # We have to do this to get around issubclass weirdness when loading plugins.

	parser = argparse.ArgumentParser(add_help=False, description='Network reconnaissance tool to port scan and automatically enumerate services found on multiple targets.')
	parser.add_argument('targets', action='store', help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.', nargs='*')
	parser.add_argument('-t', '--targets', action='store', type=str, default='', dest='target_file', help='Read targets from file.')
	parser.add_argument('-p', '--ports', action='store', type=str, help='Comma separated list of ports / port ranges to scan. Specify TCP/UDP ports by prepending list with T:/U: To scan both TCP/UDP, put port(s) at start or specify B: e.g. 53,T:21-25,80,U:123,B:123. Default: %(default)s')
	parser.add_argument('-m', '--max-scans', action='store', type=int, help='The maximum number of concurrent scans to run. Default: %(default)s')
	parser.add_argument('-mp', '--max-port-scans', action='store', type=int, help='The maximum number of concurrent port scans to run. Default: 10 (approx 20%% of max-scans unless specified)')
	parser.add_argument('-c', '--config', action='store', type=str, default=os.path.dirname(os.path.realpath(__file__)) + '/config.toml', dest='config_file', help='Location of AutoRecon\'s config file. Default: %(default)s')
	parser.add_argument('-g', '--global-file', action='store', type=str, dest='global_file', help='Location of AutoRecon\'s global file. Default: ' + os.path.dirname(os.path.realpath(__file__)) + '/global.toml')
	parser.add_argument('--tags', action='store', type=str, default='default', help='Tags to determine which plugins should be included. Separate tags by a plus symbol (+) to group tags together. Separate groups with a comma (,) to create multiple groups. For a plugin to be included, it must have all the tags specified in at least one group. Default: %(default)s')
	parser.add_argument('--exclude-tags', action='store', type=str, default='', help='Tags to determine which plugins should be excluded. Separate tags by a plus symbol (+) to group tags together. Separate groups with a comma (,) to create multiple groups. For a plugin to be excluded, it must have all the tags specified in at least one group. Default: %(default)s')
	parser.add_argument('--plugins-dir', action='store', type=str, help='The location of the plugins directory. Default: %(default)s')
	parser.add_argument('--add-plugins-dir', action='store', type=str, help='The location of an additional plugins directory to add to the main one. Default: %(default)s')
	parser.add_argument('-l', '--list', action='store', nargs='?', const='plugins', help='List all plugins or plugins of a specific type. e.g. --list, --list port, --list service')
	parser.add_argument('-o', '--output', action='store', dest='outdir', help='The output directory for results. Default: %(default)s')
	parser.add_argument('--single-target', action='store_true', help='Only scan a single target. A directory named after the target will not be created. Instead, the directory structure will be created within the output directory. Default: %(default)s')
	parser.add_argument('--only-scans-dir', action='store_true', help='Only create the "scans" directory for results. Other directories (e.g. exploit, loot, report) will not be created. Default: %(default)s')
	parser.add_argument('--create-port-dirs', action='store_true', help='Create directories for ports within the "scans" directory (e.g. scans/tcp80, scans/udp53) and store results in these directories. Default: %(default)s')
	parser.add_argument('--heartbeat', action='store', type=int, help='Specifies the heartbeat interval (in seconds) for scan status messages. Default: %(default)s')
	parser.add_argument('--timeout', action='store', type=int, help='Specifies the maximum amount of time in minutes that AutoRecon should run for. Default: %(default)s')
	parser.add_argument('--target-timeout', action='store', type=int, help='Specifies the maximum amount of time in minutes that a target should be scanned for before abandoning it and moving on. Default: %(default)s')
	nmap_group = parser.add_mutually_exclusive_group()
	nmap_group.add_argument('--nmap', action='store', help='Override the {nmap_extra} variable in scans. Default: %(default)s')
	nmap_group.add_argument('--nmap-append', action='store', help='Append to the default {nmap_extra} variable in scans. Default: %(default)s')
	parser.add_argument('--disable-sanity-checks', action='store_true', help='Disable sanity checks that would otherwise prevent the scans from running. Default: %(default)s')
	parser.add_argument('--disable-keyboard-control', action='store_true', help='Disables keyboard control ([s]tatus, Up, Down) if you are in SSH or Docker.')
	parser.add_argument('--force-services', action='store', nargs='+', help='A space separated list of services in the following style: tcp/80/http/insecure tcp/443/https/secure')
	parser.add_argument('--accessible', action='store_true', help='Attempts to make AutoRecon output more accessible to screenreaders. Default: %(default)s')
	parser.add_argument('-v', '--verbose', action='count', help='Enable verbose output. Repeat for more verbosity.')
	parser.add_argument('--version', action='store_true', help='Prints the AutoRecon version and exits.')
	parser.error = lambda s: fail(s[0].upper() + s[1:])
	args, unknown = parser.parse_known_args()

	errors = False

	autorecon.argparse = parser

	if args.version:
		print('AutoRecon v2.0-beta2')
		sys.exit(0)

	# Parse config file and args for global.toml first.
	if not os.path.isfile(args.config_file):
		fail('Error: Specified config file "' + args.config_file + '" does not exist.')

	with open(args.config_file) as c:
		try:
			config_toml = toml.load(c)
			for key, val in config_toml.items():
				key = slugify(key)
				if key == 'global-file':
					autorecon.config['global_file'] = val
				elif key == 'plugins-dir':
					autorecon.config['plugins_dir'] = val
				elif key == 'add-plugins-dir':
					autorecon.config['add_plugins_dir'] = val
		except toml.decoder.TomlDecodeError:
			fail('Error: Couldn\'t parse ' + args.config_file + ' config file. Check syntax.')

	args_dict = vars(args)
	for key in args_dict:
		key = slugify(key)
		if key == 'global-file' and args_dict['global_file'] is not None:
			autorecon.config['global_file'] = args_dict['global_file']
		elif key == 'plugins-dir' and args_dict['plugins_dir'] is not None:
			autorecon.config['plugins_dir'] = args_dict['plugins_dir']
		elif key == 'add-plugins-dir' and args_dict['add_plugins_dir'] is not None:
			autorecon.config['add_plugins_dir'] = args_dict['add_plugins_dir']

	if not os.path.isdir(autorecon.config['plugins_dir']):
		fail('Error: Specified plugins directory "' + autorecon.config['plugins_dir'] + '" does not exist.')

	if autorecon.config['add_plugins_dir'] and not os.path.isdir(autorecon.config['add_plugins_dir']):
		fail('Error: Specified additional plugins directory "' + autorecon.config['add_plugins_dir'] + '" does not exist.')

	plugins_dirs = [autorecon.config['plugins_dir']]
	if autorecon.config['add_plugins_dir']:
		plugins_dirs.append(autorecon.config['add_plugins_dir'])

	for plugins_dir in plugins_dirs:
		for plugin_file in os.listdir(plugins_dir):
			if not plugin_file.startswith('_') and plugin_file.endswith('.py'):

				dirname, filename = os.path.split(os.path.join(plugins_dir, plugin_file))
				dirname = os.path.abspath(dirname)

				# Temporarily insert the plugin directory into the sys.path so importing plugins works.
				sys.path.insert(1, dirname)

				try:
					plugin = importlib.import_module(filename[:-3])
					# Remove the plugin directory from the path after import.
					sys.path.pop(1)
					clsmembers = inspect.getmembers(plugin, predicate=inspect.isclass)
					for (_, c) in clsmembers:
						if c.__module__ == 'autorecon':
							continue

						if c.__name__.lower() in autorecon.config['protected_classes']:
							print('Plugin "' + c.__name__ + '" in ' + filename + ' is using a protected class name. Please change it.')
							sys.exit(1)

						# Only add classes that are a sub class of either PortScan or ServiceScan
						if issubclass(c, PortScan) or issubclass(c, ServiceScan):
							autorecon.register(c(), filename)
						else:
							print('Plugin "' + c.__name__ + '" in ' + filename + ' is not a subclass of either PortScan or ServiceScan.')
				except (ImportError, SyntaxError) as ex:
					print('cannot import ' + filename + ' plugin')
					print(ex)
					sys.exit(1)

	for plugin in autorecon.plugins.values():
		if plugin.slug in autorecon.taglist:
			fail('Plugin ' + plugin.name + ' has a slug (' + plugin.slug + ') with the same name as a tag. Please either change the plugin name or override the slug.')
		# Add plugin slug to tags.
		plugin.tags += [plugin.slug]

	if len(autorecon.plugin_types['port']) == 0:
		fail('Error: There are no valid PortScan plugins in the plugins directory "' + autorecon.config['plugins_dir'] + '".')

	# Sort plugins by priority.
	autorecon.plugin_types['port'].sort(key=lambda x: x.priority)
	autorecon.plugin_types['service'].sort(key=lambda x: x.priority)

	if not os.path.isfile(autorecon.config['global_file']):
		fail('Error: Specified global file "' + autorecon.config['global_file'] + '" does not exist.')

	global_plugin_args = None
	with open(autorecon.config['global_file']) as g:
		try:
			global_toml = toml.load(g)
			for key, val in global_toml.items():
				if key == 'global' and isinstance(val, dict): # Process global plugin options.
					for gkey, gvals in global_toml['global'].items():
						if isinstance(gvals, dict):
							options = {'metavar':'VALUE'}

							if 'default' in gvals:
								options['default'] = gvals['default']

							if 'metavar' in gvals:
								options['metavar'] = gvals['metavar']

							if 'help' in gvals:
								options['help'] = gvals['help']

							if 'type' in gvals:
								gtype = gvals['type'].lower()
								if gtype == 'constant':
									if 'constant' not in gvals:
										fail('Global constant option ' + gkey + ' has no constant value set.')
									else:
										options['action'] = 'store_const'
										options['const'] = gvals['constant']
								elif gtype == 'true':
									options['action'] = 'store_true'
									options.pop('metavar', None)
									options.pop('default', None)
								elif gtype == 'false':
									options['action'] = 'store_false'
									options.pop('metavar', None)
									options.pop('default', None)
								elif gtype == 'list':
									options['nargs'] = '+'
								elif gtype == 'choice':
									if 'choices' not in gvals:
										fail('Global choice option ' + gkey + ' has no choices value set.')
									else:
										if not isinstance(gvals['choices'], list):
											fail('The \'choices\' value for global choice option ' + gkey + ' should be a list.')
										options['choices'] = gvals['choices']
										options.pop('metavar', None)

							if global_plugin_args is None:
								global_plugin_args = parser.add_argument_group("global plugin arguments", description="These are optional arguments that can be used by all plugins.")

							global_plugin_args.add_argument('--global.' + slugify(gkey), **options)
				elif key == 'pattern' and isinstance(val, list): # Process global patterns.
					for pattern in val:
						if 'pattern' in pattern:
							try:
								compiled = re.compile(pattern['pattern'])
								if 'description' in pattern:
									autorecon.patterns.append(Pattern(compiled, description=pattern['description']))
								else:
									autorecon.patterns.append(Pattern(compiled))
							except re.error:
								fail('Error: The pattern "' + pattern['pattern'] + '" in the global file is invalid regex.')
						else:
							fail('Error: A [[pattern]] in the global file doesn\'t have a required pattern variable.')

		except toml.decoder.TomlDecodeError:
			fail('Error: Couldn\'t parse ' + g.name + ' file. Check syntax.')

	other_options = []
	for key, val in config_toml.items():
		if key == 'global' and isinstance(val, dict): # Process global plugin options.
			for gkey, gval in config_toml['global'].items():
				if isinstance(gval, bool):
					for action in autorecon.argparse._actions:
						if action.dest == 'global.' + slugify(gkey).replace('-', '_'):
							if action.const is True:
								action.__setattr__('default', gval)
							break
				else:
					if autorecon.argparse.get_default('global.' + slugify(gkey).replace('-', '_')):
						autorecon.argparse.set_defaults(**{'global.' + slugify(gkey).replace('-', '_'): gval})
		elif isinstance(val, dict): # Process potential plugin arguments.
			for pkey, pval in config_toml[key].items():
				if autorecon.argparse.get_default(slugify(key).replace('-', '_') + '.' + slugify(pkey).replace('-', '_')):
					autorecon.argparse.set_defaults(**{slugify(key).replace('-', '_') + '.' + slugify(pkey).replace('-', '_'): pval})
		else: # Process potential other options.
			key = key.replace('-', '_')
			if key in autorecon.configurable_keys:
				other_options.append(key)
				autorecon.config[key] = val
				autorecon.argparse.set_defaults(**{key: val})

	for key, val in autorecon.config.items():
		if key not in other_options:
			autorecon.argparse.set_defaults(**{key: val})

	parser.add_argument('-h', '--help', action='help', default=argparse.SUPPRESS, help='Show this help message and exit.')
	args = parser.parse_args()

	args_dict = vars(args)
	for key in args_dict:
		if key in autorecon.configurable_keys and args_dict[key] is not None:
			# Special case for booleans
			if key in autorecon.configurable_boolean_keys and autorecon.config[key]:
				continue
			autorecon.config[key] = args_dict[key]
	autorecon.args = args

	if args.list:
		type = args.list.lower()
		if type in ['plugin', 'plugins', 'port', 'ports', 'portscan', 'portscans']:
			for p in autorecon.plugin_types['port']:
				print('PortScan: ' + p.name + ' (' + p.slug + ')' + (' - ' + p.description if p.description else ''))
		if type in ['plugin', 'plugins', 'service', 'services', 'servicescan', 'servicescans']:
			for p in autorecon.plugin_types['service']:
				print('ServiceScan: ' + p.name + ' (' + p.slug + ')' + (' - ' + p.description if p.description else ''))

		sys.exit(0)

	if autorecon.config['ports']:
		ports_to_scan = {'tcp':[], 'udp':[]}
		unique = {'tcp':[], 'udp':[]}

		ports = autorecon.config['ports'].split(',')
		mode = 'both'
		for port in ports:
			port = port.strip()
			if port == '':
				continue

			if port.startswith('B:'):
				mode = 'both'
				port = port.split('B:')[1]
			elif port.startswith('T:'):
				mode = 'tcp'
				port = port.split('T:')[1]
			elif port.startswith('U:'):
				mode = 'udp'
				port = port.split('U:')[1]

			match = re.search('^([0-9]+)\-([0-9]+)$', port)
			if match:
				num1 = int(match.group(1))
				num2 = int(match.group(2))

				if num1 > 65535:
					fail('Error: A provided port number was too high: ' + str(num1))

				if num2 > 65535:
					fail('Error: A provided port number was too high: ' + str(num2))

				if num1 == num2:
					port_range = [num1]

				if num2 > num1:
					port_range = list(range(num1, num2 + 1, 1))
				else:
					port_range = list(range(num2, num1 + 1, 1))
					num1 = num1 + num2
					num2 = num1 - num2
					num1 = num1 - num2

				if mode == 'tcp' or mode == 'both':
					for num in port_range:
						if num in ports_to_scan['tcp']:
							ports_to_scan['tcp'].remove(num)
					ports_to_scan['tcp'].append(str(num1) + '-' + str(num2))
					unique['tcp'] = list(set(unique['tcp'] + port_range))

				if mode == 'udp' or mode == 'both':
					for num in port_range:
						if num in ports_to_scan['udp']:
							ports_to_scan['udp'].remove(num)
					ports_to_scan['udp'].append(str(num1) + '-' + str(num2))
					unique['udp'] = list(set(unique['tcp'] + port_range))
			else:
				match = re.search('^[0-9]+$', port)
				if match:
					num = int(port)

					if num > 65535:
						fail('Error: A provided port number was too high: ' + str(num))

					if mode == 'tcp' or mode == 'both':
						ports_to_scan['tcp'].append(str(num)) if num not in unique['tcp'] else ports_to_scan['tcp']
						unique['tcp'].append(num)

					if mode == 'udp' or mode == 'both':
						ports_to_scan['udp'].append(str(num)) if num not in unique['udp'] else ports_to_scan['udp']
						unique['udp'].append(num)
				else:
					fail('Error: Invalid port number: ' + str(port))
		autorecon.config['ports'] = ports_to_scan

	if autorecon.config['max_scans'] <= 0:
		error('Argument -m/--max-scans must be at least 1.')
		errors = True

	if autorecon.config['max_port_scans'] is None:
		autorecon.config['max_port_scans'] = max(1, round(autorecon.config['max_scans'] * 0.2))
	else:
		if autorecon.config['max_port_scans'] <= 0:
			error('Argument -mp/--max-port-scans must be at least 1.')
			errors = True

		if autorecon.config['max_port_scans'] > autorecon.config['max_scans']:
			error('Argument -mp/--max-port-scans cannot be greater than argument -m/--max-scans.')
			errors = True

	if autorecon.config['heartbeat'] <= 0:
		error('Argument --heartbeat must be at least 1.')
		errors = True

	if autorecon.config['timeout'] is not None and autorecon.config['timeout'] <= 0:
		error('Argument --timeout must be at least 1.')
		errors = True

	if autorecon.config['target_timeout'] is not None and autorecon.config['target_timeout'] <= 0:
		error('Argument --target-timeout must be at least 1.')
		errors = True

	if autorecon.config['timeout'] is not None and autorecon.config['target_timeout'] is not None and autorecon.config['timeout'] < autorecon.config['target_timeout']:
		error('Argument --timeout cannot be less than --target-timeout.')
		errors = True

	if not errors:
		if autorecon.config['force_services']:
			autorecon.service_scan_semaphore = asyncio.Semaphore(autorecon.config['max_scans'])
		else:
			autorecon.port_scan_semaphore = asyncio.Semaphore(autorecon.config['max_port_scans'])
			# If max scans and max port scans is the same, the service scan semaphore and port scan semaphore should be the same object
			if autorecon.config['max_scans'] == autorecon.config['max_port_scans']:
				autorecon.service_scan_semaphore = autorecon.port_scan_semaphore
			else:
				autorecon.service_scan_semaphore = asyncio.Semaphore(autorecon.config['max_scans'] - autorecon.config['max_port_scans'])

	tags = []
	for tag_group in list(set(filter(None, args.tags.lower().split(',')))):
		tags.append(list(set(filter(None, tag_group.split('+')))))

	# Remove duplicate lists from list.
	[autorecon.tags.append(t) for t in tags if t not in autorecon.tags]

	excluded_tags = []
	if args.exclude_tags is None:
		args.exclude_tags = ''
	if args.exclude_tags != '':
		for tag_group in list(set(filter(None, args.exclude_tags.lower().split(',')))):
			excluded_tags.append(list(set(filter(None, tag_group.split('+')))))

		# Remove duplicate lists from list.
		[autorecon.excluded_tags.append(t) for t in excluded_tags if t not in autorecon.excluded_tags]

	raw_targets = args.targets

	if len(args.target_file) > 0:
		if not os.path.isfile(args.target_file):
			error('The target file ' + args.target_file + ' was not found.')
			sys.exit(1)
		try:
			with open(args.target_file, 'r') as f:
				lines = f.read()
				for line in lines.splitlines():
					line = line.strip()
					if line.startswith('#'): continue
					match = re.match('([^#]+)#', line)
					if match:
						line = match.group(1).strip()
					if len(line) == 0: continue
					if line not in raw_targets:
						raw_targets.append(line)
		except OSError:
			error('The target file ' + args.target_file + ' could not be read.')
			sys.exit(1)

	for target in raw_targets:
		try:
			ip = ipaddress.ip_address(target)
			ip_str = str(ip)

			found = False
			for t in autorecon.pending_targets:
				if t.address == ip_str:
					found = True
					break

			if found:
				continue

			if isinstance(ip, ipaddress.IPv4Address):
				autorecon.pending_targets.append(Target(ip_str, 'IPv4', 'ip', autorecon))
			elif isinstance(ip, ipaddress.IPv6Address):
				autorecon.pending_targets.append(Target(ip_str, 'IPv6', 'ip', autorecon))
			else:
				fail('This should never happen unless IPv8 is invented.')
		except ValueError:

			try:
				target_range = ipaddress.ip_network(target, strict=False)
				if not args.disable_sanity_checks and target_range.num_addresses > 256:
					error(target + ' contains ' + str(target_range.num_addresses) + ' addresses. Check that your CIDR notation is correct. If it is, re-run with the --disable-sanity-checks option to suppress this check.')
					errors = True
				else:
					for ip in target_range.hosts():
						ip_str = str(ip)

						found = False
						for t in autorecon.pending_targets:
							if t.address == ip_str:
								found = True
								break

						if found:
							continue

						if isinstance(ip, ipaddress.IPv4Address):
							autorecon.pending_targets.append(Target(ip_str, 'IPv4', 'ip', autorecon))
						elif isinstance(ip, ipaddress.IPv6Address):
							autorecon.pending_targets.append(Target(ip_str, 'IPv6', 'ip', autorecon))
						else:
							fail('This should never happen unless IPv8 is invented.')

			except ValueError:

				try:
					addresses = socket.getaddrinfo(target, None, socket.AF_INET)

					found = False
					for t in autorecon.pending_targets:
						if t.address == target:
							found = True
							break

					if found:
						continue

					autorecon.pending_targets.append(Target(target, 'IPv4', 'hostname', autorecon))
				except socket.gaierror:
					try:
						addresses = socket.getaddrinfo(target, None, socket.AF_INET6)

						found = False
						for t in autorecon.pending_targets:
							if t.address == target:
								found = True
								break

						if found:
							continue

						autorecon.pending_targets.append(Target(target, 'IPv6', 'hostname', autorecon))
					except socket.gaierror:
						error(target + ' does not appear to be a valid IP address, IP range, or resolvable hostname.')
						errors = True

	if len(autorecon.pending_targets) == 0:
		error('You must specify at least one target to scan!')
		errors = True

	if autorecon.config['single_target'] and len(autorecon.pending_targets) != 1:
		error('You cannot provide more than one target when scanning in single-target mode.')
		errors = True

	if not args.disable_sanity_checks and len(autorecon.pending_targets) > 256:
		error('A total of ' + str(len(autorecon.pending_targets)) + ' targets would be scanned. If this is correct, re-run with the --disable-sanity-checks option to suppress this check.')
		errors = True

	if not autorecon.config['force_services']:
		port_scan_plugin_count = 0
		for plugin in autorecon.plugin_types['port']:
			matching_tags = False
			for tag_group in autorecon.tags:
				if set(tag_group).issubset(set(plugin.tags)):
					matching_tags = True
					break

			excluded_tags = False
			for tag_group in autorecon.excluded_tags:
				if set(tag_group).issubset(set(plugin.tags)):
					excluded_tags = True
					break

			if matching_tags and not excluded_tags:
				port_scan_plugin_count += 1

		if port_scan_plugin_count == 0:
			error('There are no port scan plugins that match the tags specified.')
			errors = True
	else:
		port_scan_plugin_count = autorecon.config['max_port_scans'] / 5

	if errors:
		sys.exit(1)

	autorecon.config['port_scan_plugin_count'] = port_scan_plugin_count

	num_initial_targets = max(1, math.ceil(autorecon.config['max_port_scans'] / port_scan_plugin_count))

	start_time = time.time()

	pending = []
	i = 0
	while autorecon.pending_targets:
		pending.append(asyncio.create_task(scan_target(autorecon.pending_targets.pop(0))))
		i+=1
		if i >= num_initial_targets:
			break

	if not autorecon.config['disable_keyboard_control']:
		tty.setcbreak(sys.stdin.fileno())
		keyboard_monitor = asyncio.create_task(keyboard())

	timed_out = False
	while pending:
		done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED, timeout=1)

		# If something failed in scan_target, autorecon.errors will be true.
		if autorecon.errors:
			cancel_all_tasks(None, None)
			sys.exit(1)

		# Check if global timeout has occurred.
		if autorecon.config['timeout'] is not None:
			elapsed_seconds = round(time.time() - start_time)
			m, s = divmod(elapsed_seconds, 60)
			if m >= autorecon.config['timeout']:
				timed_out = True
				break

		for task in done:
			if autorecon.pending_targets:
				pending.add(asyncio.create_task(scan_target(autorecon.pending_targets.pop(0))))
			if task in pending:
				pending.remove(task)

		port_scan_task_count = 0
		for targ in autorecon.scanning_targets:
			for process_list in targ.running_tasks.values():
				# If we're not scanning ports, count ServiceScans instead.
				if autorecon.config['force_services']:
					if issubclass(process_list['plugin'].__class__, ServiceScan): # TODO should we really count ServiceScans? Test...
						port_scan_task_count += 1
				else:
					if issubclass(process_list['plugin'].__class__, PortScan):
						port_scan_task_count += 1

		num_new_targets = math.ceil((autorecon.config['max_port_scans'] - port_scan_task_count) / port_scan_plugin_count)
		if num_new_targets > 0:
			i = 0
			while autorecon.pending_targets:
				pending.add(asyncio.create_task(scan_target(autorecon.pending_targets.pop(0))))
				i+=1
				if i >= num_new_targets:
					break

	keyboard_monitor.cancel()

	if timed_out:
		cancel_all_tasks(None, None)

		elapsed_time = calculate_elapsed_time(start_time)
		warn('{byellow}AutoRecon took longer than the specified timeout period (' + str(autorecon.config['timeout']) + ' min). Cancelling all scans and exiting.{rst}')
	else:
		while len(asyncio.all_tasks()) > 1: # this code runs in the main() task so it will be the only task left running
			await asyncio.sleep(1)

		elapsed_time = calculate_elapsed_time(start_time)
		info('{bright}Finished scanning all targets in ' + elapsed_time + '!{rst}')
		info('{bright}Don\'t forget to check out more commands to run manually in the _manual_commands.txt file in each target\'s scans directory!')

	if autorecon.missing_services:
		warn('{byellow}AutoRecon identified the following services, but could not match them to any plugins based on the service name. Please report these to Tib3rius: ' + ', '.join(autorecon.missing_services) + '{rst}')

	if not autorecon.config['disable_keyboard_control']:
		# Restore original terminal settings.
		termios.tcsetattr(sys.stdin, termios.TCSADRAIN, terminal_settings)

if __name__ == '__main__':
	# Capture Ctrl+C and cancel everything.
	signal.signal(signal.SIGINT, cancel_all_tasks)
	try:
		asyncio.run(main())
	except asyncio.exceptions.CancelledError:
		pass
