import subprocess

def fix_rootkits():
    """Attempts to remove detected rootkits using rkhunter."""
    try:
        subprocess.run(["sudo", "rkhunter", "--propupd"], check=True)
        subprocess.run(["sudo", "rkhunter", "--check", "--sk"], check=True)
        subprocess.run(["sudo", "rkhunter", "--remove"], check=True)
        print("✅ Rootkit removal complete. A system reboot is recommended.")
    except Exception as e:
        print(f"⚠️ Error removing rootkits: {e}")
