import frappe
import requests
from typing import Optional

class HetznerDNS:
    """Hetzner DNS API Integration"""
    
    BASE_URL = "https://dns.hetzner.com/api/v1"
    
    def __init__(self, api_token: str):
        self.api_token = api_token
        self.headers = {
            "Auth-API-Token": api_token,
            "Content-Type": "application/json"
        }
    
    def get_zone_id(self, domain: str) -> Optional[str]:
        """Get zone ID for a domain"""
        response = requests.get(
            f"{self.BASE_URL}/zones",
            headers=self.headers
        )
        response.raise_for_status()
        
        zones = response.json().get("zones", [])
        for zone in zones:
            if zone["name"] == domain:
                return zone["id"]
        return None
    
    def create_record(self, zone_id: str, record_type: str, name: str, value: str, ttl: int = 3600):
        """Create a DNS record"""
        data = {
            "zone_id": zone_id,
            "type": record_type,
            "name": name,
            "value": value,
            "ttl": ttl
        }
        
        response = requests.post(
            f"{self.BASE_URL}/records",
            headers=self.headers,
            json=data
        )
        response.raise_for_status()
        return response.json()
    
    def update_record(self, record_id: str, value: str, ttl: int = 3600):
        """Update a DNS record"""
        data = {
            "value": value,
            "ttl": ttl
        }
        
        response = requests.put(
            f"{self.BASE_URL}/records/{record_id}",
            headers=self.headers,
            json=data
        )
        response.raise_for_status()
        return response.json()
    
    def get_record(self, zone_id: str, name: str, record_type: str = "A") -> Optional[dict]:
        """Get a specific DNS record"""
        response = requests.get(
            f"{self.BASE_URL}/records",
            headers=self.headers,
            params={"zone_id": zone_id}
        )
        response.raise_for_status()
        
        records = response.json().get("records", [])
        for record in records:
            if record["name"] == name and record["type"] == record_type:
                return record
        return None
    
    def delete_record(self, record_id: str):
        """Delete a DNS record"""
        response = requests.delete(
            f"{self.BASE_URL}/records/{record_id}",
            headers=self.headers
        )
        response.raise_for_status()
        return True
    
    def upsert_record(self, domain: str, subdomain: str, value: str, record_type: str = "A"):
        """Create or update a DNS record"""
        zone_id = self.get_zone_id(domain)
        if not zone_id:
            raise Exception(f"Zone not found for domain: {domain}")
        
        record_name = f"{subdomain}.{domain}" if subdomain else domain
        existing_record = self.get_record(zone_id, record_name, record_type)
        
        if existing_record:
            # Update existing record
            return self.update_record(existing_record["id"], value)
        else:
            # Create new record
            return self.create_record(zone_id, record_type, record_name, value)


def create_hetzner_dns_record(site_doc, proxy_ip: str):
    """
    Create DNS record in Hetzner for a site
    """
    try:
        # Get Root Domain
        domain_doc = frappe.get_doc("Root Domain", site_doc.domain)
        
        # Get Hetzner API token
        api_token = domain_doc.get_password("hetzner_api_token", raise_exception=False)
        if not api_token:
            frappe.log_error(
                title=f"Hetzner API token not found for {domain_doc.name}",
                message="Please configure Hetzner API token in Root Domain"
            )
            return False
        
        # Initialize Hetzner DNS client
        dns = HetznerDNS(api_token)
        
        # Create/update DNS record
        result = dns.upsert_record(
            domain=site_doc.domain,
            subdomain=site_doc.subdomain,
            value=proxy_ip,
            record_type="A"
        )
        
        frappe.msgprint(f"DNS record created/updated for {site_doc.name}")
        return True
        
    except Exception as e:
        frappe.log_error(
            title=f"Hetzner DNS creation failed for {site_doc.name}",
            message=str(e)
        )
        frappe.throw(f"Failed to create DNS record: {str(e)}")
        return False