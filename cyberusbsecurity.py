import tkinter as tk
from tkinter import ttk, messagebox, Toplevel, Text
import webbrowser, os, random, string, smtplib, json, hashlib
from email.message import EmailMessage
from datetime import datetime
import time, cv2, logging, wmi, threading, winreg, ctypes, sys

# --- Logging setup ---
logging.basicConfig(
    filename="intruder_cam.log",
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)

# === Email Configuration ===
EMAIL_ADDRESS = "rafiyareenu19@gmail.com"
EMAIL_PASSWORD = "xtsu zivh dpwm pzqe"
ADMIN_EMAIL = EMAIL_ADDRESS

# === HTML Report ===
html_report_path = "usb_security_report.html"
html_content = "<html><body><h1>USB Security Report</h1></body></html>"
if not os.path.exists(html_report_path):
    with open(html_report_path, "w", encoding="utf-8") as f:
        f.write(html_content)

def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def set_usb_registry(value):
    try:
        reg_path = r"SYSTEM\CurrentControlSet\Services\USBSTOR"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, reg_path, 0,
                            winreg.KEY_SET_VALUE | winreg.KEY_WOW64_64KEY) as key:
            winreg.SetValueEx(key, "Start", 0, winreg.REG_DWORD, value)
        return True
    except Exception as e:
        logging.error(f"Registry error: {e}")
        return False

# === User Management ===
USERS_FILE = "users.json"

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return {"admin": {"email": ADMIN_EMAIL, "password": hash_password("admin123"), "approved": True}}

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

def generate_temp_password():
    return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(8))

def send_email(to_email, subject, body):
    try:
        msg = EmailMessage()
        msg['Subject'] = subject
        msg['From'] = EMAIL_ADDRESS
        msg['To'] = to_email
        msg.set_content(body)
        with smtplib.SMTP_SSL('smtp.gmail.com', 465) as smtp:
            smtp.login(EMAIL_ADDRESS, EMAIL_PASSWORD)
            smtp.send_message(msg)
        return True
    except Exception as e:
        logging.error(f"Email error: {e}")
        return False

def register_user(email):
    users = load_users()
    if any(user["email"] == email for user in users.values()):
        return False, "Email already registered"
    username = email.split("@")[0]
    while username in users:
        username += str(random.randint(1, 999))
    temp_pass = generate_temp_password()
    users[username] = {"email": email, "password": hash_password(temp_pass), "approved": False}
    save_users(users)
    send_email(email, "USB Control Panel Access", f"Your temporary password: {temp_pass}")
    send_email(ADMIN_EMAIL, "New Registration", f"Approve user: {username}")
    return True, "Registered. Check email."

def approve_user(username):
    users = load_users()
    if username not in users:
        return False, "User not found"
    users[username]["approved"] = True
    save_users(users)
    send_email(users[username]["email"], "Account Approved", "You're approved!")
    return True, f"Approved {username}"

def reject_user(username):
    users = load_users()
    if username not in users:
        return False, "User not found"
    send_email(users[username]["email"], "Rejected", "Your access request was rejected.")
    del users[username]
    save_users(users)
    return True, f"Rejected {username}"

# === Intruder Camera ===
def capture_intruder_video(duration=5):
    try:
        ts = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"intruder_{ts}.avi"
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            logging.warning("Webcam not found")
            return
        out = cv2.VideoWriter(filename, cv2.VideoWriter_fourcc(*'XVID'), 20.0, (640, 480))
        start = time.time()
        while time.time() - start < duration:
            ret, frame = cap.read()
            if ret: out.write(frame)
        cap.release()
        out.release()
        messagebox.showwarning("Intruder!", f"Video saved: {filename}")
    except Exception as e:
        logging.error(f"Camera error: {e}")

# === USB Check ===
def check_usb_status():
    c = wmi.WMI()
    usb_drives = []
    for disk in c.Win32_DiskDrive():
        if 'USB' in disk.InterfaceType:
            usb_drives.append({
                'DeviceID': disk.DeviceID,
                'Model': disk.Model,
                'Size (GB)': round(int(disk.Size) / (1024 ** 3), 2) if disk.Size else "Unknown"
            })
    window = Toplevel()
    window.title("USB Devices")
    text = Text(window, font=("Arial", 10))
    text.pack(expand=True, fill="both", padx=10, pady=10)
    if usb_drives:
        text.insert("end", "[INFO] USB device(s) connected:\n\n")
        for d in usb_drives:
            text.insert("end", f"• {d['Model']} ({d['DeviceID']}) — {d['Size (GB)']} GB\n")
    else:
        text.insert("end", "No USB devices connected.")
    text.config(state="disabled")

# === GUI ===
class USBControlApp:
    def __init__(self, root):
        self.root = root
        self.root.title("USB Control Panel")
        self.root.geometry("500x520")
        self.current_user = None
        if not os.path.exists(USERS_FILE):
            save_users({"admin": {"email": ADMIN_EMAIL, "password": hash_password("admin123"), "approved": True}})
        self.setup_auth_ui()

    def setup_auth_ui(self):
        for w in self.root.winfo_children(): w.destroy()
        frame = ttk.Frame(self.root, padding="20"); frame.pack(expand=True)
        ttk.Label(frame, text="USB Control Panel", font=('Helvetica', 16)).grid(row=0, column=0, columnspan=2, pady=10)
        ttk.Label(frame, text="Email:").grid(row=1, column=0)
        self.email_entry = ttk.Entry(frame); self.email_entry.grid(row=1, column=1, pady=5)
        ttk.Label(frame, text="Password:").grid(row=2, column=0)
        self.pass_entry = ttk.Entry(frame, show="*"); self.pass_entry.grid(row=2, column=1, pady=5)
        ttk.Button(frame, text="Login", command=self.login).grid(row=3, column=0, columnspan=2, pady=10)
        ttk.Button(frame, text="Register", command=self.show_register).grid(row=4, column=0, columnspan=2)
        self.auth_status = ttk.Label(frame, text="", foreground="red")
        self.auth_status.grid(row=5, column=0, columnspan=2)

    def show_register(self):
        win = tk.Toplevel(self.root); win.title("Register"); win.geometry("300x120")
        ttk.Label(win, text="Email:").grid(row=0, column=0, padx=5, pady=10)
        email = ttk.Entry(win, width=30); email.grid(row=0, column=1)
        email.focus()
        def do_register():
            em = email.get().strip()
            if "@" not in em: return messagebox.showerror("Error", "Enter valid email")
            success, msg = register_user(em)
            messagebox.showinfo("Registration", msg)
            if success: win.destroy()
        frame = ttk.Frame(win); frame.grid(row=1, column=0, columnspan=2)
        ttk.Button(frame, text="Register", command=do_register).pack(side=tk.LEFT, padx=5)
        ttk.Button(frame, text="Cancel", command=win.destroy).pack(side=tk.LEFT, padx=5)

    def login(self):
        email, password = self.email_entry.get().strip(), self.pass_entry.get().strip()
        users = load_users()
        user = next((u for u, d in users.items() if d["email"] == email), None)
        if not email or not password:
            self.auth_status.config(text="Enter all fields")
        elif not user:
            self.auth_status.config(text="User not found")
            threading.Thread(target=capture_intruder_video, daemon=True).start()
        elif not users[user]["approved"]:
            self.auth_status.config(text="Account not approved")
            threading.Thread(target=capture_intruder_video, daemon=True).start()
        elif users[user]["password"] != hash_password(password):
            self.auth_status.config(text="Incorrect password")
            threading.Thread(target=capture_intruder_video, daemon=True).start()
        else:
            self.current_user = user
            self.show_main_ui()

    def show_main_ui(self):
        for w in self.root.winfo_children(): w.destroy()
        frame = ttk.Frame(self.root, padding=10); frame.pack(fill=tk.BOTH, expand=True)
        welcome = f"Welcome, {self.current_user}!"
        if self.current_user == "admin": welcome += " (Administrator)"
        ttk.Label(frame, text=welcome, font=('Helvetica', 14)).pack(pady=10)
        btn_frame = ttk.Frame(frame); btn_frame.pack()
        if self.current_user == "admin":
            ttk.Button(btn_frame, text="Enable USB", width=15, command=self.enable_usb).pack(side=tk.LEFT, padx=5)
            ttk.Button(btn_frame, text="Disable USB", width=15, command=self.disable_usb).pack(side=tk.LEFT, padx=5)
        ttk.Button(frame, text="Check USB Status", command=check_usb_status).pack(fill=tk.X, pady=5)
        ttk.Button(frame, text="Project Info", command=self.open_project_info).pack(fill=tk.X, pady=5)
        if self.current_user == "admin":
            ttk.Label(frame, text="Admin Panel", font=('Helvetica', 12)).pack(pady=5)
            ttk.Button(frame, text="Manage Users", command=self.manage_users).pack(fill=tk.X, pady=5)
        ttk.Button(frame, text="Logout", command=self.logout).pack(fill=tk.X, pady=20)

    def enable_usb(self):
        if not is_admin(): return messagebox.showerror("Admin Required", "Run as administrator.")
        if set_usb_registry(3): messagebox.showinfo("Success", "USB enabled after restart.")
        else: messagebox.showerror("Error", "Failed to enable USB.")

    def disable_usb(self):
        if not is_admin(): return messagebox.showerror("Admin Required", "Run as administrator.")
        if set_usb_registry(4): messagebox.showinfo("Success", "USB disabled after restart.")
        else: messagebox.showerror("Error", "Failed to disable USB.")

    def open_project_info(self):
        webbrowser.open(f"file://{os.path.abspath(html_report_path)}")

    def logout(self):
        self.current_user = None
        self.setup_auth_ui()

    def manage_users(self):
        users = load_users()
        win = tk.Toplevel(self.root); win.title("User Management"); win.geometry("400x300"); win.grab_set()
        tree = ttk.Treeview(win, columns=("Email", "Approved"), show="headings")
        tree.heading("Email", text="Email"); tree.heading("Approved", text="Approved")
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        for username, data in users.items():
            if username != "admin":
                tree.insert("", tk.END, iid=username, values=(data["email"], "Yes" if data["approved"] else "No"))
        def approve_selected():
            for username in tree.selection():
                success, msg = approve_user(username)
                if success: tree.set(username, "Approved", "Yes")
                messagebox.showinfo("Approve", msg)
        def reject_selected():
            for username in tree.selection():
                success, msg = reject_user(username)
                if success: tree.delete(username)
                messagebox.showinfo("Reject", msg)
        btn_frame = ttk.Frame(win); btn_frame.pack(pady=10)
        ttk.Button(btn_frame, text="Approve", command=approve_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Reject", command=reject_selected).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Close", command=win.destroy).pack(side=tk.LEFT, padx=5)

# === Entry Point ===
if __name__ == "__main__":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        exit()
    root = tk.Tk()
    app = USBControlApp(root)
    root.mainloop()
