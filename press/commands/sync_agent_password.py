import os
import sys
import requests
import frappe

# --- CONFIG ---
FRAPPE_SITE_PATH = "/home/frappe/evoqpress"   # path to your bench folder
SITE_NAME = "evoq.app"                  # your Press site name
AGENT_ENV_PATH = "/home/frappe/agent/.env"    # path to Agent's .env file
AGENT_PORT = 25052                            # default agent port

# --- Load Frappe Environment ---
sys.path.append(FRAPPE_SITE_PATH)
frappe.init(site=SITE_NAME)
frappe.connect()
frappe.local.lang = frappe.db.get_default("lang") or "en"


def get_agent_env_password(env_path):
    """Read AGENT_PASSWORD from the .env file."""
    if not os.path.exists(env_path):
        print(f"❌ .env file not found at {env_path}")
        return None

    with open(env_path) as f:
        for line in f:
            if line.strip().startswith("AGENT_PASSWORD="):
                return line.strip().split("=", 1)[1].strip()
    print("⚠️ AGENT_PASSWORD not found in .env file.")
    return None


def sync_agent_password():
    """Compare Press Server password and Agent password, then fix if mismatched."""
    agent_password = get_agent_env_password(AGENT_ENV_PATH)
    if not agent_password:
        print("❌ Could not read agent password from .env")
        return None

    servers = frappe.get_all("Server", fields=["name", "agent_password", "provider", "ip"])
    if not servers:
        print("⚠️ No servers found in Press.")
        return None

    for server in servers:
        if not server.agent_password:
            print(f"⚠️ Server {server.name} has no agent password set.")
            continue

        if server.agent_password != agent_password:
            print(f"🔄 Updating password for {server.name} (Provider: {server.provider})...")
            srv_doc = frappe.get_doc("Server", server.name)
            srv_doc.agent_password = agent_password
            srv_doc.save(ignore_permissions=True)
            frappe.db.commit()
            print(f"✅ Password updated for {server.name}")
        else:
            print(f"✅ Password already correct for {server.name}")

        # Test agent connectivity after sync
        if server.ip:
            test_agent_ping(server.ip, AGENT_PORT)
        else:
            print(f"⚠️ Server {server.name} has no IP set, skipping ping test.")


def test_agent_ping(ip, port):
    """Test connection to Agent via /ping endpoint."""
    url = f"http://{ip}:{port}/ping"
    print(f"🌐 Testing agent connection at: {url}")
    try:
        res = requests.get(url, timeout=5)
        if res.status_code == 200 and "pong" in res.text:
            print(f"✅ Agent responded successfully: {res.text}")
        else:
            print(f"⚠️ Unexpected agent response: {res.text}")
    except requests.exceptions.RequestException as e:
        print(f"❌ Failed to connect to Agent: {e}")


if __name__ == "__main__":
    print("🔍 Starting Agent password sync and connectivity check...\n")
    sync_agent_password()
    print("\n🎯 Agent password sync and connectivity check completed.")

