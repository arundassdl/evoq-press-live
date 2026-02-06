import requests
import frappe
from frappe import _

class HetznerDNS:
    """Hetzner DNS provider for Press TLS certificate automation."""

    def __init__(self, api_token: str, domain: str):
        self.api_token = api_token
        self.domain = domain.rstrip(".")
        self.base_url = "https://dns.hetzner.com/api/v1"

    def _headers(self):
        return {
            "Auth-API-Token": self.api_token,
            "Content-Type": "application/json"
        }

    def get_zone_id(self):
        """Get the Hetzner Zone ID for the domain."""
        resp = requests.get(f"{self.base_url}/zones", headers=self._headers())
        resp.raise_for_status()
        zones = resp.json().get("zones", [])
        for zone in zones:
            if zone["name"] == self.domain or self.domain.endswith(zone["name"]):
                return zone["id"]
        raise Exception(_("No matching zone found for {0}").format(self.domain))

    def create_txt_record(self, name: str, value: str, ttl: int = 120):
        """Create TXT record for ACME challenge."""
        zone_id = self.get_zone_id()
        data = {
            "type": "TXT",
            "name": name,
            "value": value,
            "ttl": ttl,
            "zone_id": zone_id
        }
        resp = requests.post(f"{self.base_url}/records", headers=self._headers(), json=data)
        resp.raise_for_status()
        record_id = resp.json()["record"]["id"]
        frappe.logger().info(f"[HetznerDNS] Created TXT record {name}={value}")
        return record_id

    def delete_txt_record(self, record_id: str):
        """Delete TXT record after ACME validation."""
        resp = requests.delete(f"{self.base_url}/records/{record_id}", headers=self._headers())
        resp.raise_for_status()
        frappe.logger().info(f"[HetznerDNS] Deleted TXT record {record_id}")
        return True

    def add_acme_challenge(self, domain, token, value):
        """Create _acme-challenge record for Let's Encrypt validation."""
        name = f"_acme-challenge.{domain}".rstrip(".")
        return self.create_txt_record(name, value)

    def remove_acme_challenge(self, record_id):
        """Remove _acme-challenge record."""
        return self.delete_txt_record(record_id)
