import subprocess

def fix_unused_accounts():
    """Disables or deletes user accounts inactive for 90+ days."""
    try:
        result = subprocess.run(["lastlog", "-b", "90"], capture_output=True, text=True)
        users_to_disable = []

        for line in result.stdout.split("\n"):
            if "Never logged in" in line or line.strip():
                user = line.split()[0]
                users_to_disable.append(user)
        
        for user in users_to_disable:
            subprocess.run(["sudo", "usermod", "--expiredate", "1", user])  # Disable the user
            print(f"✅ Disabled unused account: {user}")
    
    except Exception as e:
        print(f"⚠️ Error disabling unused accounts: {e}")
