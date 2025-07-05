import re
import requests
import base64
import tkinter as tk
import time
from dotenv import load_dotenv
import os

# 🔐 Load API key from .env
load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VT_API_KEY")

def is_suspicious_local(url):
    suspicious_patterns = [
        r"@+",  # @ in URLs is often a sign of obfuscation
        r"https?:\/\/[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+",  # IP-based URLs
        r"(login|verify|update)[\.\-/]",  # Common phishing keywords
        r"[a-zA-Z0-9\-]{40,}",  # Very long random subdomains or tokens
        r"https?:\/\/(?!www\.).*\.com\.",  # Nested domains like fake.com.paypal.com
        r"[-_]{2,}",  # Suspicious excessive dashes or underscores
        r"(account|bank|secure|ebay|paypal)",  # High-risk words
    ]
    for pattern in suspicious_patterns:
        if re.search(pattern, url):
            return True
    return False

def check_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # Step 1: Submit URL to VirusTotal
    submit_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(submit_url, headers=headers, data={"url": url})
    if response.status_code != 200:
        return "⚠️ VirusTotal submission failed."

    # Step 2: Encode the URL to get proper report ID
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    report_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    # Step 3: Retry fetching report
    for attempt in range(15):
        report = requests.get(report_url, headers=headers).json()
        stats = report.get("data", {}).get("attributes", {}).get("last_analysis_stats")

        if stats:
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            if malicious > 0 or suspicious > 0:
                return f"🚨 VirusTotal: {malicious} malicious, {suspicious} suspicious"
            else:
                return "✅ VirusTotal: No engines flagged this URL."

        result_label.config(text=f"⏳ Waiting for VT scan... Attempt {attempt + 1}/15")
        root.update()
        time.sleep(2)

    return "⚠️ VirusTotal: Report not ready after retries."

def check_url():
    url = url_entry.get().strip()
    if not url:
        result_label.config(text="⚠️ Please enter a URL.")
        return

    result_label.config(text="🔎 Scanning...")
    root.update()

    local_flag = is_suspicious_local(url.lower())
    local_result = "✅ Safe (Local Rules)" if not local_flag else "🚨 Suspicious (Local Rules)"

    vt_result = check_virustotal(url)

    result_label.config(text=f"{local_result}\n{vt_result}")

# 🖼 GUI Setup
root = tk.Tk()
root.title("Phishing URL Detector")
root.geometry("600x360")
root.configure(bg="black")

frame = tk.Frame(root, bg="green", padx=4, pady=4)
frame.pack(pady=20)

inner_frame = tk.Frame(frame, bg="black")
inner_frame.pack()

tk.Label(inner_frame, text="Enter URL to Analyze:", fg="green", bg="black", font=("Courier", 13)).pack(pady=(10, 6))

entry_border = tk.Frame(inner_frame, bg="green", padx=2, pady=2)
entry_border.pack()
url_entry = tk.Entry(entry_border, width=55, fg="green", bg="black", insertbackground="green", font=("Courier", 11), bd=0)
url_entry.pack()

button_border = tk.Frame(inner_frame, bg="green", pady=2, padx=2)
button_border.pack(pady=16)
check_button = tk.Button(button_border, text="Check URL", command=check_url, fg="green", bg="black", font=("Courier", 12), bd=0, activebackground="black", activeforeground="green")
check_button.pack()

result_label = tk.Label(root, text="", fg="green", bg="black", font=("Courier", 11), justify="left")
result_label.pack(pady=12)

root.mainloop()
