import subprocess
from utils.security_log import log_fix

def fix_outdated_packages():
    print("\n🛠️ Updating outdated packages...")

    try:
        subprocess.run(["sudo", "apt", "update"], check=True)
        subprocess.run(["sudo", "apt", "upgrade", "-y"], check=True)

        log_fix("✅ Updated system packages.")
        print("✅ Fix applied and logged!")

    except Exception as e:
        log_fix(f"❌ Error updating packages: {e}")

if __name__ == "__main__":
    fix_outdated_packages()
