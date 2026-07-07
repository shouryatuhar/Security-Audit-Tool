import subprocess

def apply_ssh_fixes():
    print("\n🛠️  Applying SSH Fixes...")
    
    ssh_config_path = "/etc/ssh/sshd_config"
    
    subprocess.run(["sudo", "sed", "-i", "s/^PermitRootLogin yes/PermitRootLogin no/", ssh_config_path])
    
    print("🔧 Restarting SSH service...")
    subprocess.run(["sudo", "systemctl", "restart", "ssh"], check=False)

    print("✅ SSH fixes applied successfully!")
