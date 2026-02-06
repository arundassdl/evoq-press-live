# -*- coding: utf-8 -*-
# Custom override for Server._setup_server to use subprocess instead of broken Python Ansible API

import subprocess
import frappe
from frappe.utils import get_traceback


def setup_server_subprocess(self):
    """
    Custom implementation of _setup_server using subprocess instead of Python Ansible API
    This fixes the issue with Ansible 2.16.3 + Python 3.12.3 compatibility
    """
    agent_password = self.get_password("agent_password")
    agent_repository_url = self.get_agent_repository_url()
    certificate = self.get_certificate()
    log_server, kibana_password = self.get_log_server()
    agent_sentry_dsn = frappe.db.get_single_value("Press Settings", "agent_sentry_dsn")
    monitoring_password = self.get_monitoring_password()
    
    # Use server IP as log_server for self-hosted if not set
    if not log_server and getattr(self, "is_self_hosted", False):
        log_server = self.ip
        kibana_password = monitoring_password or "TempP@ss123"
    
    # Determine which playbook to use
    playbook_name = "self_hosted.yml" if getattr(self, "is_self_hosted", False) else "server.yml"
    playbook_path = frappe.get_app_path("press", "playbooks", playbook_name)
    
    try:
        # Build the ansible-playbook command
        cmd = [
            'ansible-playbook',
            '-i', f'{self.ip},',
            '-u', self._ssh_user(),
            '--private-key', '/home/frappe/.ssh/id_rsa',
            playbook_path,
            '-e', f'server={self.name}',
            '-e', f'private_ip={self.private_ip}',
            '-e', f'proxy_ip={self.get_proxy_ip()}',
            '-e', 'workers=2',
            '-e', f'agent_password={agent_password}',
            '-e', f'agent_repository_url={agent_repository_url}',
            '-e', f'agent_sentry_dsn={agent_sentry_dsn or ""}',
            '-e', f'monitoring_password={monitoring_password}',
            '-e', f'log_server={log_server or ""}',
            '-e', f'kibana_password={kibana_password or ""}',
            '-e', f'certificate_private_key={certificate.private_key}',
            '-e', f'certificate_full_chain={certificate.full_chain}',
            '-e', f'certificate_intermediate_chain={certificate.intermediate_chain}',
            '-e', f'docker_depends_on_mounts={str(self.docker_depends_on_mounts).lower()}',
        ]
        
        # Add mount variables
        mount_vars = self.get_mount_variables()
        for key, value in mount_vars.items():
            cmd.extend(['-e', f'{key}={value}'])
        
        # Add SSH port if not default
        ssh_port = self._ssh_port()
        if ssh_port != 22:
            cmd.extend(['-e', f'ansible_port={ssh_port}'])
        
        # Log the execution
        frappe.logger().info(f"Running Ansible setup for {self.name} via subprocess")
        
        # Execute ansible-playbook with timeout
        result = subprocess.run(
            cmd, 
            capture_output=True, 
            text=True, 
            timeout=2400  # 40 minutes timeout
        )
        
        if result.returncode == 0:
            # Success
            self.reload()
            self.status = "Active"
            self.is_server_setup = True
            frappe.logger().info(f"Server {self.name} setup completed successfully")
        else:
            # Failure
            self.status = "Broken"
            error_msg = result.stderr[-1000:] if result.stderr else "Unknown error"
            frappe.logger().error(f"Server {self.name} setup failed: {error_msg}")
            
    except subprocess.TimeoutExpired:
        self.status = "Broken"
        frappe.logger().error(f"Server {self.name} setup timed out after 40 minutes")
        
    except Exception as e:
        self.status = "Broken"
        frappe.log_error(
            title=f"Server Setup Exception: {self.name}",
            message=get_traceback()
        )
        frappe.logger().error(f"Server {self.name} setup exception: {str(e)}")
        
    finally:
        self.save()


# Monkey-patch the Server class
def apply_server_patch(bootinfo=None):
    """Apply the custom _setup_server override"""
    from press.press.doctype.server.server import Server
    
    # Store original method as backup
    if not hasattr(Server, '_setup_server_original'):
        Server._setup_server_original = Server._setup_server
    
    # Replace with subprocess version
    Server._setup_server = setup_server_subprocess
    
    frappe.logger().info("Applied custom Server._setup_server subprocess patch")
