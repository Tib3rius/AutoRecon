from autorecon.plugins import Report
from autorecon.config import config
import os, glob

class Markdown(Report):

	def __init__(self):
		super().__init__()
		self.name = 'Markdown'

	async def run(self, targets):
		if len(targets) > 1:
			report = os.path.join(config['output'], 'report.md')
		elif len(targets) == 1:
			report = os.path.join(targets[0].reportdir, 'report.md')
		else:
			return

		os.makedirs(report, exist_ok=True)

		for target in targets:
			os.makedirs(os.path.join(report, target.address), exist_ok=True)

			files = [os.path.abspath(filename) for filename in glob.iglob(os.path.join(target.scandir, '**/*'), recursive=True) if os.path.isfile(filename) and filename.endswith(('.txt', '.html'))]

			if target.scans['ports']:
				os.makedirs(os.path.join(report, target.address, 'Port Scans'), exist_ok=True)
				for scan in target.scans['ports'].keys():
					if len(target.scans['ports'][scan]['commands']) > 0:
						with open(os.path.join(report, target.address, 'Port Scans', 'PortScan - ' + target.scans['ports'][scan]['plugin'].name + '.md'), 'w') as output:
							for command in target.scans['ports'][scan]['commands']:
								output.writelines('```bash\n' + command[0] + '\n```')
								for filename in files:
									if filename in command[0] or (command[1] is not None and filename == command[1]) or (command[2] is not None and filename == command[2]):
										output.writelines('\n\n[' + filename + '](file://' + filename + '):\n\n')
										with open(filename, 'r') as file:
											output.writelines('```\n' + file.read() + '\n```\n')
			if target.scans['services']:
				os.makedirs(os.path.join(report, target.address, 'Services'), exist_ok=True)
				for service in target.scans['services'].keys():
					os.makedirs(os.path.join(report, target.address, 'Services', 'Service - ' + service.tag().replace('/', '-')), exist_ok=True)
					for plugin in target.scans['services'][service].keys():
						if len(target.scans['services'][service][plugin]['commands']) > 0:
							with open(os.path.join(report, target.address, 'Services', 'Service - ' + service.tag().replace('/', '-'), target.scans['services'][service][plugin]['plugin'].name + '.md'), 'w') as output:
								for command in target.scans['services'][service][plugin]['commands']:
									output.writelines('```bash\n' + command[0] + '\n```')
									for filename in files:
										if filename in command[0] or (command[1] is not None and filename == command[1]) or (command[2] is not None and filename == command[2]):
											output.writelines('\n\n[' + filename + '](file://' + filename + '):\n\n')
											with open(filename, 'r') as file:
												output.writelines('```\n' + file.read() + '\n```\n')

			manual_commands = os.path.join(target.scandir, '_manual_commands.txt')
			if os.path.isfile(manual_commands):
				with open(os.path.join(report, target.address, 'Manual Commands' + '.md'), 'w') as output:
					with open(manual_commands, 'r') as file:
						output.writelines('```bash\n' + file.read() + '\n```')

			patterns = os.path.join(target.scandir, '_patterns.log')
			if os.path.isfile(patterns):
				with open(os.path.join(report, target.address, 'Patterns' + '.md'), 'w') as output:
					with open(patterns, 'r') as file:
						output.writelines(file.read())

			commands = os.path.join(target.scandir, '_commands.log')
			if os.path.isfile(commands):
				with open(os.path.join(report, target.address, 'Commands' + '.md'), 'w') as output:
					with open(commands, 'r') as file:
						output.writelines('```bash\n' + file.read() + '\n```')

			errors = os.path.join(target.scandir, '_errors.log')
			if os.path.isfile(errors):
				with open(os.path.join(report, target.address, 'Errors' + '.md'), 'w') as output:
					with open(errors, 'r') as file:
						output.writelines('```\n' + file.read() + '\n```')
