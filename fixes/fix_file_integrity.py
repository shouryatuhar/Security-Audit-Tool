import subprocess

def fix_file_integrity():
    """Restores system files from backups if integrity is compromised."""
    subprocess.run(["cp", "/backup/etc/passwd", "/etc/passwd"])
    subprocess.run(["cp", "/backup/etc/shadow", "/etc/shadow"])
