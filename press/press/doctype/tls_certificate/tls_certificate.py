# Copyright (c) 2020, Frappe and contributors
# For license information, please see license.txt
from __future__ import annotations

import os
import re
import shlex
import subprocess
import time
from contextlib import suppress
from datetime import datetime
from typing import TYPE_CHECKING

import frappe
import OpenSSL
from frappe.model.document import Document
from frappe.query_builder.functions import Date

from press.api.site import check_dns_cname_a
from press.exceptions import (
	DNSValidationError,
	TLSRetryLimitExceeded,
)
from press.overrides import get_permission_query_conditions_for_doctype
from press.press.doctype.communication_info.communication_info import get_communication_info
from press.runner import Ansible
from press.utils import get_current_team, log_error

if TYPE_CHECKING:
	from press.press.doctype.ansible_play.ansible_play import AnsiblePlay

AUTO_RETRY_LIMIT = 5
MANUAL_RETRY_LIMIT = 8

from press.press.doctype.tls_certificate.hetzner_dns import HetznerDNS

class TLSCertificate(Document):
	# begin: auto-generated types
	# This code is auto-generated. Do not modify anything in this block.

	from typing import TYPE_CHECKING

	if TYPE_CHECKING:
		from frappe.types import DF

		certificate: DF.Code | None
		decoded_certificate: DF.Code | None
		domain: DF.Data
		error: DF.Code | None
		expires_on: DF.Datetime | None
		full_chain: DF.Code | None
		intermediate_chain: DF.Code | None
		issued_on: DF.Datetime | None
		private_key: DF.Code | None
		provider: DF.Literal["Let's Encrypt", "Other"]
		retry_count: DF.Int
		rsa_key_size: DF.Literal["2048", "3072", "4096"]
		status: DF.Literal["Pending", "Active", "Expired", "Revoked", "Failure"]
		team: DF.Link | None
		wildcard: DF.Check
	# end: auto-generated types

	def autoname(self):
		if self.wildcard:
			self.name = f"*.{self.domain}"
		else:
			self.name = self.domain

	def after_insert(self):
		self.obtain_certificate()

	def validate(self):
		if self.provider == "Other":
			if not self.team:
				frappe.throw("Team is mandatory for custom TLS certificates.")

			self.configure_full_chain()
			self.validate_key_length()
			self.validate_key_certificate_association()
			self._extract_certificate_details()

	def on_update(self):
		if self.is_new():
			return

		if self.has_value_changed("rsa_key_size"):
			self.obtain_certificate()

	@frappe.whitelist()
	def obtain_certificate(self):
		if self.provider != "Let's Encrypt":
			return

		if self.retry_count >= MANUAL_RETRY_LIMIT:
			frappe.throw("Retry limit exceeded. Please check the error and try again.", TLSRetryLimitExceeded)
		(
			user,
			session_data,
			team,
		) = (
			frappe.session.user,
			frappe.session.data,
			get_current_team(),
		)

		frappe.set_user(frappe.get_value("Team", team, "user"))
		frappe.enqueue_doc(
			self.doctype,
			self.name,
			"_obtain_certificate",
			enqueue_after_commit=True,
			job_id=f"obtain_certificate:{self.name}",
			deduplicate=True,
		)
		frappe.set_user(user)
		frappe.session.data = session_data

	@frappe.whitelist()
	def _obtain_certificate(self):
		if self.provider != "Let's Encrypt":
			return
		try:
			settings = frappe.get_doc("Press Settings", "Press Settings")
			ca = LetsEncrypt(settings, tls_certificate_doc=self)
			(
				self.certificate,
				self.full_chain,
				self.intermediate_chain,
				self.private_key,
			) = ca.obtain(
				domain=self.domain,
				rsa_key_size=self.rsa_key_size,
				wildcard=self.wildcard,
				dns_challenge_provider=self.dns_challenge_provider,
			)
			self._extract_certificate_details()
			self.status = "Active"
			self.retry_count = 0
			self.error = None
		except Exception as e:
			# If certbot is already running, retry after 5 seconds
			# TODO: Move this to a queue
			if hasattr(e, "output") and e.output:
				out = e.output.decode()
				if "Another instance of Certbot is already running" in out:
					time.sleep(5)
					frappe.enqueue_doc(
						self.doctype,
						self.name,
						"_obtain_certificate",
						job_id=f"obtain_certificate:{self.name}",
						deduplicate=True,
					)
					return
				if re.search(r"Detail: .*: Invalid response", out):
					self.error = "Suggestion: You may have updated your DNS records recently. Please wait for the changes to propagate. Please try fetching certificate after some time."
					self.error += "\n" + out
				else:
					self.error = out
			else:
				self.error = repr(e)
			self.retry_count += 1
			self.status = "Failure"
			log_error("TLS Certificate Exception", certificate=self.name)
		self.save()
		self.trigger_site_domain_callback()
		self.trigger_self_hosted_server_callback()
		if self.wildcard:
			self.trigger_server_tls_setup_callback()
			self._update_secondary_wildcard_domains()

	def _update_secondary_wildcard_domains(self):
		"""
		Install secondary wildcard domains on proxies.

		Skip install on servers using the same domain for it's own hostname.
		"""
		proxies_containing_domain = frappe.get_all(
			"Proxy Server Domain", {"domain": self.domain}, pluck="parent"
		)
		proxies_using_domain = frappe.get_all("Proxy Server", {"domain": self.domain}, pluck="name")
		proxies_containing_domain = set(proxies_containing_domain) - set(proxies_using_domain)
		for proxy_name in proxies_containing_domain:
			proxy = frappe.get_doc("Proxy Server", proxy_name)
			proxy.setup_wildcard_hosts()

	@frappe.whitelist()
	def trigger_server_tls_setup_callback(self):
		server_doctypes = [
			"Proxy Server",
			"Server",
			"Database Server",
			"Log Server",
			"Monitor Server",
			"Registry Server",
			"Analytics Server",
			"Trace Server",
		]

		for server_doctype in server_doctypes:
			servers = frappe.get_all(
				server_doctype,
				filters={
					"status": ("not in", ["Archived", "Installing"]),
					"name": ("like", f"%.{self.domain}"),
				},
				fields=["name", "status"],
			)
			for server in servers:
				if server.status == "Active":
					frappe.enqueue(
						"press.press.doctype.tls_certificate.tls_certificate.update_server_tls_certifcate",
						server=frappe.get_doc(server_doctype, server.name),
						certificate=self,
						enqueue_after_commit=True,
					)
				else:
					# If server is not active, mark the tls_certificate_renewal_failed field as True
					frappe.db.set_value(
						server_doctype,
						server.name,
						"tls_certificate_renewal_failed",
						1,
						update_modified=False,
					)

	@frappe.whitelist()
	def trigger_site_domain_callback(self):
		domain = frappe.db.get_value("Site Domain", {"tls_certificate": self.name}, "name")
		if domain:
			frappe.get_doc("Site Domain", domain).process_tls_certificate_update()

	def trigger_self_hosted_server_callback(self):
		with suppress(Exception):
			frappe.get_doc("Self Hosted Server", self.name).process_tls_cert_update()

	def _extract_certificate_details(self):
		x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.certificate)
		self.decoded_certificate = OpenSSL.crypto.dump_certificate(
			OpenSSL.crypto.FILETYPE_TEXT, x509
		).decode()
		self.issued_on = datetime.strptime(x509.get_notBefore().decode(), "%Y%m%d%H%M%SZ")
		self.expires_on = datetime.strptime(x509.get_notAfter().decode(), "%Y%m%d%H%M%SZ")

	def configure_full_chain(self):
		if not self.full_chain:
			self.full_chain = f"{self.certificate}\n{self.intermediate_chain}"

	# def _get_private_key_object(self):
	# 	try:
	# 		return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, self.private_key)
	# 	except OpenSSL.crypto.Error as e:
	# 		log_error("TLS Private Key Exception", certificate=self.name)
	# 		raise e

	# def _get_certificate_object(self):
	# 	try:
	# 		return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, self.full_chain)
	# 	except OpenSSL.crypto.Error as e:
	# 		log_error("Custom TLS Certificate Exception", certificate=self.name)
	# 		raise e

	from OpenSSL import crypto

	def _get_private_key_object(self):
		"""
		Load the private key from the PEM file.
		Returns OpenSSL.crypto.PKey object.
		"""
		try:
			# If self.private_key is a file path, read its contents
			if isinstance(self.private_key, str):
				with open(self.private_key, "rb") as f:
					private_key_data = f.read()
			else:
				private_key_data = self.private_key

			return OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, private_key_data)
		except Exception as e:
			frappe.log_error(frappe.get_traceback(), "TLS Private Key Load Error")
			raise e


	def _get_certificate_object(self, cert_path=None):
		"""
		Load the certificate from PEM file.
		Returns OpenSSL.crypto.X509 object.
		"""
		try:
			path = cert_path or self.certificate
			if isinstance(path, str):
				with open(path, "rb") as f:
					cert_data = f.read()
			else:
				cert_data = path

			return OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert_data)
		except Exception as e:
			frappe.log_error(frappe.get_traceback(), "TLS Certificate Load Error")
			raise e


	def validate_key_length(self):
		private_key = self._get_private_key_object()

		if private_key.bits() != int(self.rsa_key_size):
			frappe.throw(
				f"Private key length does not match the selected RSA key size. Expected {self.rsa_key_size} bits, got {private_key.bits()} bits."
			)

	def validate_key_certificate_association(self):
		context = OpenSSL.SSL.Context(OpenSSL.SSL.TLSv1_METHOD)
		context.use_privatekey(self._get_private_key_object())
		context.use_certificate(self._get_certificate_object())

		try:
			context.check_privatekey()
			self.status = "Active"
			self.retry_count = 0
			self.error = None
		except OpenSSL.SSL.Error as e:
			self.error = repr(e)
			log_error("TLS Key Certificate Association Exception", certificate=self.name)
			frappe.throw("Private Key and Certificate do not match")
		finally:
			if self.error:
				self.status = "Failure"


get_permission_query_conditions = get_permission_query_conditions_for_doctype("TLS Certificate")


class PendingCertificate(frappe._dict):
	name: str
	domain: str
	wildcard: bool
	retry_count: int


def should_renew(site: str | None, certificate: PendingCertificate) -> bool:
	if certificate.wildcard:
		return True
	if not site:
		return False
	if frappe.db.get_value("Site", site, "status") != "Active":
		return False
	dns_response = check_dns_cname_a(site, certificate.domain, ignore_proxying=True)
	if dns_response["matched"]:
		return True
	raise DNSValidationError(
		f"DNS check failed. {dns_response.get('answer')}",
	)


def rollback_and_fail_tls(certificate: PendingCertificate, e: Exception):
	frappe.db.rollback()
	frappe.db.set_value(
		"TLS Certificate",
		certificate.name,
		{
			"status": "Failure",
			"error": str(e),
			"retry_count": certificate.retry_count + 1,
		},
	)


def renew_tls_certificates():
	tls_renewal_queue_size = frappe.db.get_single_value("Press Settings", "tls_renewal_queue_size")
	pending = frappe.get_all(
		"TLS Certificate",
		fields=["name", "domain", "wildcard", "retry_count"],
		filters={
			"status": ("in", ("Active", "Failure")),
			"expires_on": ("<", frappe.utils.add_days(None, 25)),
			"retry_count": ("<", AUTO_RETRY_LIMIT),
			"provider": "Let's Encrypt",
		},
		ignore_ifnull=True,
		order_by="expires_on ASC, status DESC",  # Oldest first, then prefer failures.
	)
	renewals_attempted = 0
	for certificate in pending:
		if tls_renewal_queue_size and (renewals_attempted >= tls_renewal_queue_size):
			break

		site = frappe.db.get_value("Site Domain", {"tls_certificate": certificate.name}, "site")

		try:
			if not should_renew(site, certificate):
				continue
			renewals_attempted += 1
			certificate_doc = TLSCertificate("TLS Certificate", certificate.name)
			certificate_doc._obtain_certificate()
			frappe.db.commit()
		except DNSValidationError as e:
			rollback_and_fail_tls(certificate, e)  # has to come first as it has frappe.db.rollback()
			frappe.db.set_value(
				"Site Domain",
				{"tls_certificate": certificate.name},
				{"status": "Broken", "dns_response": str(e)},
			)
			frappe.db.commit()
		except Exception as e:
			rollback_and_fail_tls(certificate, e)
			log_error("TLS Renewal Exception", certificate=certificate, site=site)
			frappe.db.commit()


def notify_custom_tls_renewal():
	seven_days = frappe.utils.add_days(None, 7).date()
	fifteen_days = frappe.utils.add_days(None, 15).date()

	tls_cert = frappe.qb.DocType("TLS Certificate")

	# Notify team members 15 days and 7 days before expiry

	query = (
		frappe.qb.from_(tls_cert)
		.select(tls_cert.name, tls_cert.domain, tls_cert.team, tls_cert.expires_on)
		.where(tls_cert.status.isin(["Active", "Failure"]))
		.where((Date(tls_cert.expires_on) == seven_days) | (Date(tls_cert.expires_on) == fifteen_days))
		.where(tls_cert.provider == "Other")
	)

	pending = query.run(as_dict=True)

	for certificate in pending:
		if certificate.team:
			notify_email = frappe.get_value("Team", certificate.team, "notify_email")

			frappe.sendmail(
				#recipients=notify_email,
				recipients=get_communication_info("Email", "Site Activity", "Team", certificate.team),
				subject=f"TLS Certificate Renewal Required: {certificate.name}",
				message=f"TLS Certificate {certificate.name} is due for renewal on {certificate.expires_on}. Please renew the certificate to avoid service disruption.",
			)


def update_server_tls_certifcate(server, certificate):
	try:
		proxysql_admin_password = None
		if server.doctype == "Proxy Server":
			proxysql_admin_password = server.get_password("proxysql_admin_password")
		ansible = Ansible(
			playbook="tls.yml",
			user=server.get("ssh_user") or "root",
			port=server.get("ssh_port") or 22,
			server=server,
			variables={
				"certificate_private_key": certificate.private_key,
				"certificate_full_chain": certificate.full_chain,
				"certificate_intermediate_chain": certificate.intermediate_chain,
				"is_proxy_server": bool(proxysql_admin_password),
				"proxysql_admin_password": proxysql_admin_password,
			},
		)
		play: "AnsiblePlay" = ansible.run()
		frappe.db.set_value(
			server.doctype,
			server.name,
			"tls_certificate_renewal_failed",
			play.status != "Success",
			# to avoid causing TimestampMismatchError in other important tasks
			update_modified=False,
		)
	except Exception:
		log_error("TLS Setup Exception", server=server.as_dict())


def retrigger_failed_wildcard_tls_callbacks():
	server_doctypes = [
		"Proxy Server",
		"Server",
		"Database Server",
		"Log Server",
		"Monitor Server",
		"Registry Server",
		"Analytics Server",
		"Trace Server",
	]
	for server_doctype in server_doctypes:
		servers = frappe.get_all(
			server_doctype, filters={"status": "Active"}, fields=["name", "tls_certificate_renewal_failed"]
		)
		for server in servers:
			previous_attempt_failed = server.tls_certificate_renewal_failed
			if not previous_attempt_failed:
				plays = frappe.get_all(
					"Ansible Play",
					{"play": "Setup TLS Certificates", "server": server.name},
					pluck="status",
					limit=1,
					order_by="creation DESC",
				)
				if plays and plays[0] != "Success":
					previous_attempt_failed = True

			if previous_attempt_failed:
				server_doc = frappe.get_doc(server_doctype, server)
				frappe.enqueue(
					"press.press.doctype.tls_certificate.tls_certificate.update_server_tls_certifcate",
					server=server_doc,
					certificate=server_doc.get_certificate(),
				)


class BaseCA:
	def __init__(self, settings):
		self.settings = settings

	def obtain(self, domain, rsa_key_size=2048, wildcard=False, dns_challenge_provider=None):
		self.domain = f"*.{domain}" if wildcard else domain
		self.rsa_key_size = rsa_key_size
		self.wildcard = wildcard
		self.dns_challenge_provider = dns_challenge_provider
		self._obtain()
		return self._extract()

	def _read_latest_certificate_file(self, file_path):
		import glob
		import os
		import re

		# Split path into directory and filename
		dir_path = os.path.dirname(file_path)
		file_name = os.path.basename(file_path)
		parent_dir = os.path.dirname(dir_path)
		base_dir_name = os.path.basename(dir_path)

		# Look for indexed directories first (e.g., dir-0000, dir-0001, etc.)
		indexed_dirs = glob.glob(os.path.join(parent_dir, f"{base_dir_name}-[0-9][0-9][0-9][0-9]"))

		if indexed_dirs:
			# Find directory with highest index
			latest_dir = max(indexed_dirs, key=lambda p: int(re.search(r"-(\d+)$", p).group(1)))
			latest_path = os.path.join(latest_dir, file_name)
		elif os.path.exists(file_path):
			latest_path = file_path
		else:
			raise FileNotFoundError(f"Certificate file not found: {file_path}")

		with open(latest_path) as f:
			return f.read()

	def _extract(self):
		certificate = self._read_latest_certificate_file(self.certificate_file)
		full_chain = self._read_latest_certificate_file(self.full_chain_file)
		intermediate_chain = self._read_latest_certificate_file(self.intermediate_chain_file)
		private_key = self._read_latest_certificate_file(self.private_key_file)
		return certificate, full_chain, intermediate_chain, private_key


class LetsEncrypt(BaseCA):
	def __init__(self, settings, tls_certificate_doc):
		super().__init__(settings)
		self.directory = settings.certbot_directory
		self.webroot_directory = settings.webroot_directory
		self.eff_registration_email = settings.eff_registration_email
		self.tls_certificate_doc = tls_certificate_doc
		self.hetzner_dns_api_token = settings.get_password("hetzner_api_token")

		# Staging CA provides certificates that are signed by an untrusted root CA
		# Only use to test certificate procurement/installation flows.
		# Reference: https://letsencrypt.org/docs/staging-environment/
		if frappe.conf.developer_mode and settings.use_staging_ca:
			self.staging = True
		else:
			self.staging = False

	def _obtain(self):
		if not os.path.exists(self.directory):
			os.mkdir(self.directory)

		if self.dns_challenge_provider == "Hetzner":
			auth_hook_path = self._create_hetzner_auth_hook_script()
			cleanup_hook_path = self._create_hetzner_cleanup_hook_script()
			# Create shell wrappers to force python interpreter
			auth_wrapper = self._create_shell_wrapper("hetzner_auth_hook.sh", auth_hook_path)
			cleanup_wrapper = self._create_shell_wrapper("hetzner_cleanup_hook.sh", cleanup_hook_path)
			self._run_certbot_with_hooks(self._certbot_command(), auth_wrapper, cleanup_wrapper)
			return

		if self.wildcard:
			self._obtain_wildcard()
		else:
			if frappe.conf.developer_mode:
				self._obtain_naked_with_dns()
			else:
				self._obtain_naked()

	def _obtain_wildcard(self):
		domain = frappe.get_doc("Root Domain", self.domain[2:])
		environment = os.environ
		environment.update(
			{
				"AWS_ACCESS_KEY_ID": domain.aws_access_key_id,
				"AWS_SECRET_ACCESS_KEY": domain.get_password("aws_secret_access_key"),
			}
		)
		self.run(self._certbot_command(), environment=environment)

	def _obtain_naked_with_dns(self):
		domain = frappe.get_all("Root Domain", pluck="name", limit=1)[0]
		domain = frappe.get_doc("Root Domain", domain)
		environment = os.environ
		environment.update(
			{
				"AWS_ACCESS_KEY_ID": domain.aws_access_key_id,
				"AWS_SECRET_ACCESS_KEY": domain.get_password("aws_secret_access_key"),
			}
		)
		self.run(self._certbot_command(), environment=environment)

	def _obtain_naked(self):
		if not os.path.exists(self.webroot_directory):
			os.mkdir(self.webroot_directory)
		self.run(self._certbot_command())

	def _certbot_command(self):
		if self.dns_challenge_provider == "Hetzner":
			plugin = "--manual --preferred-challenges dns"
		elif self.wildcard or frappe.conf.developer_mode:
			plugin = "--dns-route53"
		else:
			plugin = f"--webroot --webroot-path {self.webroot_directory}"

		staging = "--staging" if self.staging else ""
		force_renewal = "--keep" if frappe.conf.developer_mode else "--force-renewal"

		return (
			f"certbot certonly {plugin} {staging} --logs-dir"
			f" {self.directory}/logs --work-dir {self.directory} --config-dir"
			f" {self.directory} {force_renewal} --agree-tos --eff-email --email"
			f" {self.eff_registration_email} --staple-ocsp"
			" --key-type rsa"
			f" --rsa-key-size {self.rsa_key_size} --cert-name {self.domain} --domains"
			f" {self.domain}"
		)

	def run(self, command, environment=None):
		try:
			subprocess.check_output(shlex.split(command), stderr=subprocess.STDOUT, env=environment)
		except subprocess.CalledProcessError as e:
			output = (e.output or b"").decode()
			if "Another instance of Certbot is already running" not in output:
				log_error("Certbot Exception", command=command, output=output)
			raise e
		except Exception as e:
			log_error("Certbot Exception", command=command, exception=e)
			raise e

	@property
	def certificate_file(self):
		return os.path.join(self.directory, "live", self.domain, "cert.pem")

	@property
	def full_chain_file(self):
		return os.path.join(self.directory, "live", self.domain, "fullchain.pem")

	@property
	def intermediate_chain_file(self):
		return os.path.join(self.directory, "live", self.domain, "chain.pem")

	@property
	def private_key_file(self):
		return os.path.join(self.directory, "live", self.domain, "privkey.pem")

	def _create_hetzner_auth_hook_script(self):
		hook_script_content = """#!/usr/bin/env python3
import os
import sys
import json
import time
import urllib.request
import urllib.error

BASE_URL = "https://dns.hetzner.com/api/v1"

def _headers(token):
    return {"Auth-API-Token": token, "Content-Type": "application/json"}

def get_zone_id(token, domain):
    req = urllib.request.Request(f"{BASE_URL}/zones", headers=_headers(token))
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())
    zones = data.get("zones", [])
    for zone in zones:
        name = zone.get("name")
        if name and (domain == name or domain.endswith(name)):
            return zone.get("id")
    raise RuntimeError(f"No matching zone found for {domain}")

def create_txt_record(token, zone_id, name, value, ttl=120):
    payload = json.dumps({
        "type": "TXT",
        "name": name,
        "value": value,
        "ttl": ttl,
        "zone_id": zone_id,
    }).encode()
    req = urllib.request.Request(f"{BASE_URL}/records", headers=_headers(token), data=payload, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())
    return data["record"]["id"]

def list_zone_records(token, zone_id):
    req = urllib.request.Request(f"{BASE_URL}/records?zone_id={zone_id}", headers=_headers(token))
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode())
    return data.get("records", [])

def delete_record(token, record_id):
    req = urllib.request.Request(f"{BASE_URL}/records/{record_id}", headers=_headers(token), method="DELETE")
    with urllib.request.urlopen(req, timeout=30) as _:
        pass

try:
    domain = os.environ.get("CERTBOT_DOMAIN")
    validation = os.environ.get("CERTBOT_VALIDATION")
    token = os.environ.get("HETZNER_API_TOKEN")
    if not all([domain, validation, token]):
        raise ValueError("Missing required environment variables")

    parts = domain.split(".")
    base_domain = ".".join(parts[-2:]) if len(parts) >= 2 else domain
    zone_id = get_zone_id(token, base_domain)
    # Hetzner expects record 'name' relative to the zone
    if domain == base_domain:
        record_name = "_acme-challenge"
    else:
        sub = domain[: -(len(base_domain) + 1)]  # remove "." + base_domain
        record_name = f"_acme-challenge.{sub}".rstrip(".")
    # Remove any pre-existing _acme-challenge TXT records for this domain to avoid multiple values
    for rec in list_zone_records(token, zone_id):
        if rec.get("type") == "TXT" and rec.get("name") == record_name:
            try:
                delete_record(token, rec.get("id"))
            except Exception:
                pass
    record_id = create_txt_record(token, zone_id, record_name, validation, ttl=120)

    wait_s = int(os.environ.get("HETZNER_PROPAGATION_WAIT", "180"))
    time.sleep(wait_s)
    print(record_id)
except Exception as e:
    with open("/tmp/certbot-hetzner-auth-error.log", "a") as f:
        f.write("Auth hook failed: %s\\n" % e)
    sys.exit(1)
"""
		hook_script_path = os.path.join(self.directory, "hetzner_auth_hook.py")
		with open(hook_script_path, "w") as f:
			f.write(hook_script_content)
		os.chmod(hook_script_path, 0o755)  # Make the script executable
		return hook_script_path

	def _create_hetzner_cleanup_hook_script(self):
		hook_script_content = """#!/usr/bin/env python3
import os
import sys
import json
import urllib.request
import urllib.error

BASE_URL = "https://dns.hetzner.com/api/v1"

def _headers(token):
    return {"Auth-API-Token": token, "Content-Type": "application/json"}

def delete_record(token, record_id):
    req = urllib.request.Request(f"{BASE_URL}/records/{record_id}", headers=_headers(token), method="DELETE")
    with urllib.request.urlopen(req, timeout=30) as _:
        pass

try:
    record_id = os.environ.get("CERTBOT_AUTH_OUTPUT")
    token = os.environ.get("HETZNER_API_TOKEN")
    if not all([record_id, token]):
        raise ValueError("Missing required environment variables")
    delete_record(token, record_id)
except Exception as e:
    with open("/tmp/certbot-hetzner-cleanup-error.log", "a") as f:
        f.write("Cleanup hook failed: %s\\n" % e)
    sys.exit(1)
"""
		hook_script_path = os.path.join(self.directory, "hetzner_cleanup_hook.py")
		with open(hook_script_path, "w") as f:
			f.write(hook_script_content)
		os.chmod(hook_script_path, 0o755)  # Make the script executable
		return hook_script_path

	def _create_shell_wrapper(self, filename: str, target_script_path: str):
		# Deprecated: Not used anymore, kept for backward compatibility if referenced elsewhere
		wrapper_path = os.path.join(self.directory, filename)
		with open(wrapper_path, "w") as f:
			f.write("#!/bin/sh\nexit 0\n")
		os.chmod(wrapper_path, 0o755)
		return wrapper_path

	def _run_certbot_with_hooks(self, command, auth_hook_path, cleanup_hook_path):
		environment = os.environ.copy()
		environment["HETZNER_API_TOKEN"] = self.hetzner_dns_api_token # Pass encrypted token to sub-process
		
		full_command = f"{command} --manual-auth-hook /usr/bin/python3 {auth_hook_path} --manual-cleanup-hook /usr/bin/python3 {cleanup_hook_path}"
		try:
			self.run(full_command, environment=environment)
		finally:
			# Clean up the temporary hook scripts
			os.remove(auth_hook_path)
			os.remove(cleanup_hook_path)
