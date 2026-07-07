import subprocess
from utils.security_log import log_fix

def fix_weak_passwords():
    print("\n🛠️ Fixing weak passwords...")

    try:
        subprocess.run(["sudo", "passwd", "--expire", "root"], check=True)
        subprocess.run(["sudo", "passwd", "--expire", "varshith"], check=True)
        with open("/etc/security/pwquality.conf", "a") as f:
            f.write("\nminlen = 12\nucredit = -1\nlcredit = -1\ndcredit = -1\nocredit = -1\n")
        
        log_fix("✅ Enforced strong password policies and forced password reset for root/admin.")
        print("✅ Fix applied and logged!")

    except Exception as e:
        log_fix(f"❌ Error fixing weak passwords: {e}")

if __name__ == "__main__":
    fix_weak_passwords()
