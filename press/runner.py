import json

import frappe
import wrapt
from ansible import constants, context
from ansible.executor.playbook_executor import PlaybookExecutor
from ansible.executor.task_executor import TaskExecutor
from ansible.inventory.manager import InventoryManager
from ansible.module_utils.common.collections import ImmutableDict
from ansible.parsing.dataloader import DataLoader
from ansible.playbook import Playbook
from ansible.plugins.action.async_status import ActionModule
from ansible.plugins.callback import CallbackBase
from ansible.utils.display import Display
from ansible.vars.manager import VariableManager
from frappe.utils import cstr
from frappe.utils import now_datetime as now

from press.press.doctype.ansible_play.ansible_play import AnsiblePlay


def reconnect_on_failure():
	@wrapt.decorator
	def wrapper(wrapped, instance, args, kwargs):
		try:
			return wrapped(*args, **kwargs)
		except Exception as e:
			if frappe.db.is_interface_error(e):
				frappe.db.connect()
				return wrapped(*args, **kwargs)
			raise

	return wrapper


class AnsibleCallback(CallbackBase):
	def __init__(self, *args, **kwargs):
		super().__init__(*args, **kwargs)

	@reconnect_on_failure()
	def process_task_success(self, result):
		result, action = frappe._dict(result._result), result._task.action
		if action == "user":
			server_type, server = frappe.db.get_value("Ansible Play", self.play, ["server_type", "server"])
			server = frappe.get_doc(server_type, server)
			if result.name == "root":
				server.root_public_key = result.ssh_public_key
			elif result.name == "frappe":
				server.frappe_public_key = result.ssh_public_key
			server.save()

	def v2_runner_on_ok(self, result, *args, **kwargs):
		self.update_task("Success", result)
		self.process_task_success(result)

	def v2_runner_on_failed(self, result, *args, **kwargs):
		self.update_task("Failure", result)

	def v2_runner_on_skipped(self, result):
		self.update_task("Skipped", result)

	def v2_runner_on_unreachable(self, result):
		self.update_task("Unreachable", result)

#    def v2_playbook_on_task_start(self, task, is_conditional):
#		self.update_task("Running", None, task)
	def v2_playbook_on_task_start(self, task, is_conditional):
		# task is already the task object, no need for result._task
		self.update_task("Running", task=task)

	def v2_playbook_on_start(self, playbook):
		self.update_play("Running")

	def v2_playbook_on_stats(self, stats):
		# self.update_play(None, stats)
		"""Called when playbook finishes - update play status"""
		try:
			self.update_play(stats)
		except BrokenPipeError:
			# Ignore broken pipe errors during final stats
			pass
		except Exception as e:
			# Log but don't fail the playbook
			try:
				frappe.log_error(
					title="Ansible Stats Callback Error",
					message=f"Error in v2_playbook_on_stats: {str(e)}"
				)
			except:
				pass

#	@reconnect_on_failure()
#	def update_play(self, status=None, stats=None):
#		play = frappe.get_doc("Ansible Play", self.play)
#		if stats:
#			# Assume we're running on one host
#			host = next(iter(stats.processed.keys()))
#			play.update(stats.summarize(host))
#			if play.failures or play.unreachable:
#				play.status = "Failure"
#			else:
#				play.status = "Success"
#			play.end = now()
#			play.duration = play.end - play.start
#		else:
#			play.status = status
#			play.start = now()
#
#		play.save()
#		frappe.db.commit()

	@reconnect_on_failure()
	def update_play(self, stats=None):
		"""Update the Ansible Play document with final status"""
		try:
			# Reconnect to database if needed
			try:
				frappe.db.sql("SELECT 1")
			except:
				frappe.db.close()
				frappe.connect()

			play = frappe.get_doc("Ansible Play", self.play)

			if stats:
				# Update based on aggregate stats
				hosts = sorted(stats.processed.keys())
				for host in hosts:
					summary = stats.summarize(host)
					if summary.get('failures', 0) > 0 or summary.get('unreachable', 0) > 0:
						play.status = "Failure"
						break
				else:
					play.status = "Success"

			play.end = now()
			if play.start and play.end:
				from datetime import datetime
				if isinstance(play.start, str):
					start = datetime.strptime(play.start, '%Y-%m-%d %H:%M:%S.%f')
				else:
					start = play.start
				
				if isinstance(play.end, str):
					end = datetime.strptime(play.end, '%Y-%m-%d %H:%M:%S.%f')
				else:
					end = play.end
				
				play.duration = (end - start).total_seconds()
			play.save(ignore_permissions=True, ignore_version=True)
			frappe.db.commit()

		except Exception as e:
			frappe.log_error(
				title="Update Play Error",
				message=f"Error updating play {self.play}: {str(e)}"
			)

	@reconnect_on_failure()
	def update_task(self, status, result=None, task=None):
		task_name = None
		parsed_result = None
		
		# Case 1: We have a result object (from v2_runner_on_* methods)
		if result and hasattr(result, '_task'):
			task_obj = result._task
			
			# Handle tasks without roles (like "Gathering Facts")
			if not hasattr(task_obj, '_role') or not task_obj._role:
				# Use task name directly for non-role tasks
				if hasattr(task_obj, 'name') and task_obj.name:
					# Check if this task is tracked in a special way
					# For "Gathering Facts", it might be in self.tasks under a special key
					task_name = self.find_task_by_name(task_obj.name)
					if not task_name:
						frappe.log_error(
							title="Ansible Task Update - No Role Task Not Tracked",
							message=f"Non-role task not tracked: {task_obj.name}"
						)
						return
				else:
					return
			else:
				# Normal role-based task
				task_name, parsed_result = self.parse_result(result)
		
		# Case 2: We have a task object (from v2_playbook_on_task_start)
		elif task and not isinstance(task, str):
			# Handle tasks without roles
			if not hasattr(task, '_role') or not task._role:
				if hasattr(task, 'name') and task.name:
					task_name = self.find_task_by_name(task.name)
					if not task_name:
						frappe.log_error(
							title="Ansible Task Update - No Role Task Not Tracked",
							message=f"Non-role task not tracked: {task.name}"
						)
						return
				else:
					return
			else:
				# Normal role-based task
				try:
					role_name = task._role.get_name()
					if role_name in self.tasks and hasattr(task, 'name') and task.name in self.tasks[role_name]:
						task_name = self.tasks[role_name][task.name]
					else:
						return
				except Exception as e:
					frappe.log_error(
						title="Ansible Task Update - Exception",
						message=f"Error processing task: {str(e)}"
					)
					return
		else:
			return
		
		if not task_name:
			return
		
		# Update the task document (rest of your code remains the same)
		try:
			task_doc = frappe.get_doc("Ansible Task", task_name)
			task_doc.status = status
			
			if parsed_result:
				task_doc.output = parsed_result.get('stdout', '')
				task_doc.error = parsed_result.get('stderr', '')
				task_doc.exception = parsed_result.get('msg', '')
				
				for key in ("stdout", "stdout_lines", "stderr", "stderr_lines", "msg"):
					parsed_result.pop(key, None)
				
				task_doc.result = json.dumps(parsed_result, indent=4)
				task_doc.end = now()
				task_doc.duration = task_doc.end - task_doc.start
			else:
				task_doc.start = now()
			
			task_doc.save()
			self.publish_play_progress(task_doc.name)
			frappe.db.commit()
		except Exception as e:
			frappe.log_error(
				title="Ansible Task Update - Save Error",
				message=f"Error saving task {task_name}: {str(e)}"
			)


	def find_task_by_name(self, task_name):
		"""Find a task by name across all roles or in a special non-role section"""
		# Check if tasks are stored differently for non-role tasks
		# This depends on how your self.tasks dict is structured
		
		# Option 1: Check all roles
		for role_name, tasks in self.tasks.items():
			if task_name in tasks:
				return tasks[task_name]
		
		# Option 2: Check if there's a None or "" key for non-role tasks
		if None in self.tasks and task_name in self.tasks[None]:
			return self.tasks[None][task_name]
		
		if "" in self.tasks and task_name in self.tasks[""]:
			return self.tasks[""][task_name]
		
		return None

	def publish_play_progress(self, task):
		frappe.publish_realtime(
			"ansible_play_progress",
			{"progress": self.task_list.index(task), "total": len(self.task_list), "play": self.play},
			doctype="Ansible Play",
			docname=self.play,
			user=frappe.session.user,
		)

	def parse_result(self, result):
		task = result._task.name
		role = result._task._role.get_name()
		return self.tasks[role][task], frappe._dict(result._result)

	@reconnect_on_failure()
	def on_async_start(self, role, task, job_id):
		task_name = self.tasks[role][task]
		task = frappe.get_doc("Ansible Task", task_name)
		task.job_id = job_id
		task.save()
		frappe.db.commit()

	@reconnect_on_failure()
	def on_async_poll(self, result):
		job_id = result["ansible_job_id"]
		task_name = frappe.get_value("Ansible Task", {"play": self.play, "job_id": job_id}, "name")
		task = frappe.get_doc("Ansible Task", task_name)
		task.result = json.dumps(result, indent=4)
		task.duration = now() - task.start
		task.save()
		frappe.db.commit()


class Ansible:
	def __init__(self, server, playbook, user="root", variables=None, port=22):
		self.patch()
		self.server = server
		self.playbook = playbook
		self.playbook_path = frappe.get_app_path("press", "playbooks", self.playbook)
		self.host = f"{server.ip}:{port}"
		self.variables = variables or {}

		constants.HOST_KEY_CHECKING = False
		context.CLIARGS = ImmutableDict(
			become_method="sudo",
			check=False,
			connection="ssh",
			# This is the only way to pass variables that preserves newlines
			extra_vars=[f"{cstr(key)}='{cstr(value)}'" for key, value in self.variables.items()],
			remote_user=user,
			start_at_task=None,
			syntax=False,
			verbosity=1,
			ssh_common_args=self._get_ssh_proxy_commad(server),
		)

		self.loader = DataLoader()
		self.passwords = dict({})

		self.sources = f"{self.host},"
		self.inventory = InventoryManager(loader=self.loader, sources=self.sources)
		self.variable_manager = VariableManager(loader=self.loader, inventory=self.inventory)

		self.callback = AnsibleCallback()
		self.display = Display()
		self.display.verbosity = 1
		self.create_ansible_play()

	def _get_ssh_proxy_commad(self, server):
		# Note: ProxyCommand must be enclosed in double quotes
		# because it contains spaces
		# and the entire argument must be enclosed in single quotes
		# because it is passed via the CLI
		# See https://docs.ansible.com/ansible/latest/user_guide/connection_details.html#ssh-args
		# and https://unix.stackexchange.com/a/303717
		# for details
		proxy_command = None
		if hasattr(self.server, "bastion_host") and self.server.bastion_host:
			proxy_command = f'-o ProxyCommand="ssh -W %h:%p \
					{server.bastion_host.ssh_user}@{server.bastion_host.ip} \
						-p {server.bastion_host.ssh_port}"'

		return proxy_command

	def patch(self):
		def modified_action_module_run(*args, **kwargs):
			result = self.action_module_run(*args, **kwargs)
			self.callback.on_async_poll(result)
			return result

		def modified_poll_async_result(executor, result, templar, task_vars=None):
			job_id = result["ansible_job_id"]
			task = executor._task
			self.callback.on_async_start(task._role.get_name(), task.name, job_id)
			return self._poll_async_result(executor, result, templar, task_vars=task_vars)

		if ActionModule.run.__module__ != "press.runner":
			self.action_module_run = ActionModule.run
			ActionModule.run = modified_action_module_run

		if TaskExecutor.run.__module__ != "press.runner":
			self._poll_async_result = TaskExecutor._poll_async_result
			TaskExecutor._poll_async_result = modified_poll_async_result

	def unpatch(self):
		TaskExecutor._poll_async_result = self._poll_async_result
		ActionModule.run = self.action_module_run

	def run(self) -> AnsiblePlay:
		self.executor = PlaybookExecutor(
			playbooks=[self.playbook_path],
			inventory=self.inventory,
			variable_manager=self.variable_manager,
			loader=self.loader,
			passwords=self.passwords,
		)
		# Use AnsibleCallback so we can receive updates for tasks execution
		self.executor._tqm._stdout_callback = self.callback
		self.callback.play = self.play
		self.callback.tasks = self.tasks
		self.callback.task_list = self.task_list
		self.executor.run()
		self.unpatch()
		return frappe.get_doc("Ansible Play", self.play)

	def create_ansible_play(self):
		# Parse the playbook and create Ansible Tasks so we can show how many tasks are pending
		playbook = Playbook.load(
			self.playbook_path, variable_manager=self.variable_manager, loader=self.loader
		)
		# Assume we only have one play per playbook
		play = playbook.get_plays()[0]
		play_doc = frappe.get_doc(
			{
				"doctype": "Ansible Play",
				"server_type": self.server.doctype,
				"server": self.server.name,
				"variables": json.dumps(self.variables, indent=4),
				"playbook": self.playbook,
				"play": play.get_name(),
			}
		).insert()
		self.play = play_doc.name
		self.tasks = {}
		self.task_list = []
		for role in play.get_roles():
			for block in role.get_task_blocks():
				for task in block.block:
					task_doc = frappe.get_doc(
						{
							"doctype": "Ansible Task",
							"play": self.play,
							"role": role.get_name(),
							"task": task.name,
						}
					).insert()
					self.tasks.setdefault(role.get_name(), {})[task.name] = task_doc.name
					self.task_list.append(task_doc.name)

