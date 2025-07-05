# PhishingURL_DeTector

## Project Overview  
**PhishingURL_DeTector** is a Python-based tool designed to identify suspicious or potentially malicious URLs using pattern-based detection and VirusTotal API analysis. The tool features a graphical user interface (GUI) built with Tkinter, making it simple and accessible — even in Kali Linux environments. This project was developed as part of the **EncodersPro Internship Program by Byteshield** to provide hands-on experience in cybersecurity and Python development.

---

## How It Works  
The application provides a GUI where users can input a URL. Upon clicking the “Check” button, the tool performs two checks:

1. **Pattern-Based Detection**  
   Detects suspicious elements such as:
   - Use of IP addresses instead of domain names
   - Misspelled or misleading domains (e.g., `paypa1`, `secure-login`)
   - Suspicious subdomains, paths, and embedded credentials

2. **VirusTotal API Scan**  
   Submits the URL to VirusTotal and retrieves analysis from multiple antivirus engines. If the URL is new, it submits the URL and waits before fetching the final report.

The result is displayed with a clear status:
- ✅ **Safe**  
- 🚨 **Suspicious**

---

## Project Files

| File Name               | Description                                      |
|-------------------------|--------------------------------------------------|
| `PhishingURL_DeTector.py` | Main Python script with GUI and detection logic |
| `links.txt`             | Sample file containing test URLs                 |
| `requirements.txt`      | Lists all required Python libraries              |

---

## Requirements

- Python 3.x
- Libraries (installed via `requirements.txt`):
  - `requests`
  - `tkinter`
  - `python-dotenv`

Install required libraries using:
`pip install -r requirements.txt`

## 🔐 Setting Up Your API Key

This project uses the VirusTotal API, and for security reasons, the API key is stored in a `.env` file which is **not included** in the repository.

### Step-by-step:

1. Create a `.env` file in the project root folder (same level as the `.py` file).
2. Add this line:
`VIRUSTOTAL_API_KEY=your_api_key_here`
3. Replace `your_api_key_here` with your actual API key from VirusTotal.

> 🔗 You can get a free API key by signing up at:  
> [https://www.virustotal.com/gui/my-apikey](https://www.virustotal.com/gui/my-apikey)

---

## ▶️ How to Run
Step 1: Install dependencies
`pip install -r requirements.txt`

Step 2: Run the application
`python PhishingURL_DeTector.py`

-A GUI window will open.
-Enter a URL in the input field.
-Click "Check URL" to scan it.
-The result will show whether the URL is safe or suspicious.

## Why I Built This
This tool was built as part of the EncodersPro Internship Program by Byteshield to provide hands-on cybersecurity and Python development experience.
It aims to help learners:

-Understand common phishing URL patterns.
-Practice using regular expressions for detection.
-Learn how to work with public APIs like VirusTotal.
-Build a GUI-based tool using Python's tkinter module.
-Adopt safe coding practices like .env usage and version control hygiene.


