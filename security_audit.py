import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time

from config.loader import load_config
from core.models import CheckStatus
from platforms import create_engine
from reports import generate_reports
from utils.logger import log_audit_event, log_event, setup_logging

# Legacy fix modules — preserved for interactive remediation workflow
from fixes.firewall_fix import apply_firewall_fixes
from fixes.ssh_fix import apply_ssh_fixes
from fixes.password_fix import fix_weak_passwords
from fixes.outdated_packages_fix import fix_outdated_packages
from fixes.running_processes_fix import fix_suspicious_processes
from fixes.fix_open_ports import fix_open_ports
from fixes.fix_rootkits import fix_rootkits
from fixes.fix_unused_accounts import fix_unused_accounts

# Map check IDs to legacy fix functions
FIX_MAP = {
    "firewall": apply_firewall_fixes,
    "ssh_config": apply_ssh_fixes,
    "password_policy": fix_weak_passwords,
    "outdated_packages": fix_outdated_packages,
    "suspicious_processes": fix_suspicious_processes,
    "open_ports": fix_open_ports,
    "rootkit_detection": fix_rootkits,
    "unused_accounts": fix_unused_accounts,
}

CHECK_LABELS = {
    "firewall": "Firewall",
    "ssh_config": "SSH Configuration",
    "password_policy": "Weak Passwords",
    "outdated_packages": "Outdated Packages",
    "suspicious_processes": "Suspicious Processes",
    "open_ports": "Open Ports",
    "rootkit_detection": "Rootkit Detection",
    "unused_accounts": "Unused User Accounts",
    "running_services": "Running Services",
    "file_permissions": "File Permissions",
    "scheduled_tasks": "Scheduled Tasks",
    "startup_services": "Startup Services",
    "dangerous_config": "Dangerous Configuration",
    "package_inventory": "Package Inventory",
    "port_scan": "Port Scan",
    "user_privileges": "User Privileges",
    "file_integrity": "File Integrity",
}


class SecurityAuditGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HostSentinel — Security Audit")
        self.root.geometry("700x560")

        self.config = load_config()
        self.engine = create_engine(self.config)
        self.theme_var = tk.StringVar(value="light")

        header = tk.Label(
            root,
            text="🛡️ HostSentinel",
            font=("Helvetica", 16, "bold"),
        )
        header.pack(pady=(10, 0))

        sub = tk.Label(root, text="Enterprise Host Security Auditing Framework", fg="gray")
        sub.pack()

        self.check_vars = {}
        self.check_buttons_frame = tk.Frame(root)
        self.check_buttons_frame.pack(pady=10)

        for check_id in self.engine.list_checks():
            label = CHECK_LABELS.get(check_id, check_id.replace("_", " ").title())
            var = tk.BooleanVar(value=True)
            self.check_vars[check_id] = var
            tk.Checkbutton(self.check_buttons_frame, text=label, variable=var).pack(anchor="w")

        btn_frame = tk.Frame(root)
        btn_frame.pack(pady=5)

        self.run_button = tk.Button(
            btn_frame, text="▶ Run Security Audit", command=self.run_audit, width=20
        )
        self.run_button.pack(side=tk.LEFT, padx=5)

        self.score_label = tk.Label(btn_frame, text="Score: —", font=("Helvetica", 12, "bold"))
        self.score_label.pack(side=tk.LEFT, padx=10)

        self.progress_bar = ttk.Progressbar(root, length=400, mode="determinate")
        self.progress_bar.pack(pady=5)

        self.log_output = scrolledtext.ScrolledText(root, height=14, wrap=tk.WORD)
        self.log_output.pack(padx=10, pady=10, fill="both", expand=True)

        self.theme_toggle = tk.Checkbutton(
            root,
            text="Dark Mode",
            variable=self.theme_var,
            onvalue="dark",
            offvalue="light",
            command=self.toggle_theme,
        )
        self.theme_toggle.pack(pady=5)

        setup_logging(
            self.config.get("logging", {}).get("level", "INFO"),
            self.config.get("logging", {}).get("file"),
        )
        self.set_theme("light")

    def log_message(self, message):
        self.log_output.insert(tk.END, message + "\n")
        self.log_output.yview(tk.END)
        log_event(message)

    def run_audit(self):
        selected = [cid for cid, var in self.check_vars.items() if var.get()]
        if not selected:
            messagebox.showwarning("Warning", "Select at least one check to run.")
            return

        self.run_button.config(state=tk.DISABLED)
        self.log_output.delete(1.0, tk.END)
        self.progress_bar["value"] = 0
        self.score_label.config(text="Score: —")

        threading.Thread(
            target=self.perform_audit, args=(selected,), daemon=True
        ).start()

    def perform_audit(self, selected_checks):
        step = 100 / max(len(selected_checks), 1)
        issues_found = []

        report = self.engine.run(check_ids=selected_checks)

        for finding in report.findings:
            label = CHECK_LABELS.get(finding.check_id, finding.title)
            if finding.status == CheckStatus.PASS:
                self.log_message(f"✅ {label}: {finding.description}")
            elif finding.status == CheckStatus.SKIP:
                self.log_message(f"⏭️  {label}: {finding.description}")
            elif finding.status == CheckStatus.ERROR:
                self.log_message(f"⚠️  {label}: {finding.description}")
            elif finding.is_finding:
                cve = f" [{', '.join(finding.cve_ids)}]" if finding.cve_ids else ""
                self.log_message(
                    f"❌ [{finding.severity.value.upper()}] {label}: {finding.description}{cve}"
                )
                if finding.check_id in FIX_MAP:
                    issues_found.append((label, finding.check_id, FIX_MAP[finding.check_id]))
            self.progress_bar["value"] += step / max(len(report.findings), 1)
            self.root.update_idletasks()

        self.score_label.config(text=f"Score: {report.score}/100")
        self.log_message(f"\n📊 Security Score: {report.score}/100")

        try:
            paths = generate_reports(
                report,
                self.config.get("reports", {}).get("output_dir", "reports"),
                ["json", "html"],
            )
            for fmt, path in paths.items():
                self.log_message(f"📄 Report ({fmt}): {path}")
        except Exception as exc:
            self.log_message(f"Report generation note: {exc}")

        log_audit_event(f"GUI_AUDIT score={report.score}")
        self.progress_bar["value"] = 100
        self.ask_for_fix(issues_found)

    def ask_for_fix(self, issues_found):
        if not issues_found:
            messagebox.showinfo("Complete", "Audit complete — no fixable issues detected.")
            self.run_button.config(state=tk.NORMAL)
            return

        for label, check_id, fix_function in issues_found:
            apply_fix = messagebox.askyesno(
                "Apply Fix", f"{label} issue detected! Do you want to apply the legacy fix?"
            )
            if apply_fix:
                try:
                    fix_function()
                    self.log_message(f"✅ Fix applied for {label}!")
                except Exception as exc:
                    self.log_message(f"❌ Fix failed for {label}: {exc}")

        self.run_button.config(state=tk.NORMAL)

    def toggle_theme(self):
        self.set_theme(self.theme_var.get())

    def set_theme(self, theme):
        if theme == "dark":
            self.root.configure(bg="#2E2E2E")
            self.log_output.configure(bg="#3C3F41", fg="white")
        else:
            self.root.configure(bg="white")
            self.log_output.configure(bg="white", fg="black")


if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityAuditGUI(root)
    root.mainloop()
