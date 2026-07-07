import subprocess

def enable_firewall():
    print("🔧 Enabling firewall...")
    subprocess.run(["sudo", "ufw", "enable"], check=False)

def apply_firewall_fixes():
    print("\n🛠️  Applying Firewall Fixes...")
    
    status = subprocess.run(["sudo", "ufw", "status"], capture_output=True, text=True)
    if "inactive" in status.stdout:
        enable_firewall()
    
    risky_ports = [22, 3389, 445]
    for port in risky_ports:
        print(f"🔧 Closing risky port {port}...")
        subprocess.run(["sudo", "ufw", "deny", str(port)], check=False)

    print("✅ Firewall fixes applied successfully!")
