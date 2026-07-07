import subprocess
from utils.security_log import log_fix

SUSPICIOUS_PROCESSES = ["minerd", "klogd", "netcat", "nc", "nmap"]

def fix_suspicious_processes():
    print("\n🛠️ Stopping suspicious processes...")

    try:
        for process in SUSPICIOUS_PROCESSES:
            subprocess.run(["sudo", "pkill", "-f", process], check=False)
        
        log_fix(f"✅ Stopped suspicious processes: {', '.join(SUSPICIOUS_PROCESSES)}")
        print("✅ Fix applied and logged!")

    except Exception as e:
        log_fix(f"❌ Error stopping suspicious processes: {e}")

if __name__ == "__main__":
    fix_suspicious_processes()
