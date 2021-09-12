import os

configurable_keys = [
	'ports',
	'max_scans',
	'max_port_scans',
	'tags',
	'exclude_tags',
	'port_scans',
	'service_scans',
	'reports',
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
	'proxychains',
	'disable_sanity_checks',
	'disable_keyboard_control',
	'force_services',
	'accessible',
	'verbose'
]

configurable_boolean_keys = [
	'single_target',
	'only_scans_dir',
	'create_port_dirs',
	'proxychains',
	'disable_sanity_checks',
	'accessible'
]

config = {
	'protected_classes': ['autorecon', 'target', 'service', 'commandstreamreader', 'plugin', 'portscan', 'servicescan', 'global', 'pattern'],
	'global_file': os.path.dirname(os.path.realpath(os.path.join(__file__, '..'))) + '/global.toml',
	'ports': None,
	'max_scans': 50,
	'max_port_scans': None,
	'tags': 'default',
	'exclude_tags': None,
	'port_scans': None,
	'service_scans': None,
	'reports': None,
	'plugins_dir': os.path.dirname(os.path.abspath(os.path.join(__file__, '..'))) + '/plugins',
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
	'proxychains': False,
	'disable_sanity_checks': False,
	'disable_keyboard_control': False,
	'force_services': None,
	'accessible': False,
	'verbose': 0
}
