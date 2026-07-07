import subprocess
import re

def fix_open_ports():
    """Closes unnecessary open ports by disabling unused services."""
    try:
        # Get the list of open ports and their associated services
        result = subprocess.run(["netstat", "-tuln"], capture_output=True, text=True)
        open_ports = [line for line in result.stdout.split("\n") if "LISTEN" in line]

        if not open_ports:
            return
        
        closed_services = []
        for line in open_ports:
            match = re.search(r":(\d+)", line)
            if match:
                port = match.group(1)
                service_result = subprocess.run(["ss", "-tulnp"], capture_output=True, text=True)
                for service_line in service_result.stdout.split("\n"):
                    if f":{port}" in service_line:
                        match_service = re.search(r'users:\(\("([^"]+)"', service_line)
                        if match_service:
                            service_name = match_service.group(1)
                            subprocess.run(["sudo", "systemctl", "stop", service_name])
                            subprocess.run(["sudo", "systemctl", "disable", service_name])
                            closed_services.append(service_name)
        
        print(f"✅ Closed unnecessary services: {', '.join(closed_services)}")
    except Exception as e:
        print(f"⚠️ Error fixing open ports: {e}")
