
# 🛡️ Phishing Website Detection using VirusTotal API

This project implements a phishing website detection system using the **VirusTotal API**.  
The Python script submits URLs to the VirusTotal platform, which scans them against 70+ antivirus and threat engines.  
It then reports whether a website is **Safe** or **Phishing/Malicious**.  

---

## 📌 Features
- Integration with **VirusTotal API v3** for real-time URL scanning  
- Automated classification of websites into Safe ✅ or Phishing ⚠️  
- JSON-based results including malicious, suspicious, harmless, and undetected counts  
- Example test cases with both safe (Google, CBIT) and phishing (PayPal, Facebook fake login) URLs  
- Easy-to-use Python script with minimal dependencies  

---

## 📂 Repository Structure

Phishing-Website-Detection-using-VirusTotal-API/
│
├── virustotal\_check.py          # Main Python script
├── urls.txt                     # Sample test URLs (safe + phishing)
├── Outputs/                     # Screenshots of results
│   ├── safe.png                 # Example of a safe website result
│   ├── malicious.png            # Example of a phishing website result
│
├── report/
│   ├── PhishingDetection\_Report.pdf   # Final 2-page project report
│
└── README.md                    # Documentation
---

## 🚀 How to Run
1. Clone this repository:
   ```bash
   git clone https://github.com/HarshitaVu/Phishing-Website-Detection-using-VirusTotal-API.git
   cd Phishing-Website-Detection-using-VirusTotal-API
2. Install dependencies:
   bash
   pip install -r requirements.txt
3. Open virustotal_check.py` and replace `API_KEY` with your personal VirusTotal API key.

4. Run the script:
   bash
   python virustotal_check.py
---
## 📊 Results

* **Safe URLs** like `google.com`, `cbit.ac.in` were classified as harmless ✅
* **Phishing URLs** like `paypal.com.security-update-login.com` were flagged ⚠️
* Outputs are stored in the `Outputs/` folder as screenshots.

### Example Outputs

| URL                                  | Result    | Outcome     |
| ------------------------------------ | --------- | ----------- |
| google.com                           | harmless  | ✅ Safe      |
| cbit.ac.in                           | harmless  | ✅ Safe      |
| paypal.com.security-update-login.com | malicious | ⚠️ Phishing |
| facebook-security-check.com          | malicious | ⚠️ Phishing |

---
## 👩‍💻 Author
Harshita Vuthaluru
B.Tech IT-2, CBIT

---

