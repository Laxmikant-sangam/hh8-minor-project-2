# hh8-minor-project-2
IoT Device Scanner is a Python-based security auditing tool that finds and assesses the security of Internet of Things (IoT) devices on a local network. It uses Scapy for packet manipulation and the Shodan API for external information. 
A Python-based network security tool designed to scan local networks for Internet of Things (IoT) devices, identify them via MAC address vendors, and detect potential security risks such as default credentials and known vendor vulnerabilities using the Shodan API.
## 📖 Project Overview

This tool was created to automate the identification of vulnerable IoT devices on a home or office network. It combines network discovery (ARP scanning) with Open Source Intelligence (OSINT) to provide a quick security assessment.
**Key Capabilities:**
* **Network Scanning:** Discovers active devices on the Local Area Network (LAN).
* **Fingerprinting:** Identifies device manufacturers using OUI (MAC Address) lookup.
* **Vulnerability Detection:** Checks specifically for devices known to have insecure default factory passwords.
* **Threat Intelligence:** Queries the Shodan API for recent exploits related to the device manufacturer.

* ## 🛠️ Tech Stack

* **Language:** Python 3
* **Network Packet Manipulation:** Scapy
* **API Integration:** Shodan API, Macvendors.co
* **HTTP Requests:** Requests library
* **CLI Formatting:** Colorama

  ## 📋 Prerequisites

Before running the scanner, ensure you have the following:

1.  **Python 3.x** installed.
2.  **Administrator/Root privileges** (Required to send ARP packets).
3.  A **Shodan API Key** (Get a free key at [shodan.io](https://account.shodan.io/register)).

  ## 📦 Installation & Setup

1.  **Clone the Repository**
    ```bash
        git clone [https://github.com/your-username/iot-device-scanner.git](https://github.com/your-username/iot-device-scanner.git)
        cd iot-device-scanner
    ```

2.  **Install Dependencies**
    ```bash
        pip install scapy requests shodan colorama
    ```

3.  **Configure API Key**
    Open `iot_scanner.py` in a text editor and find the configuration section:
    ```python
    # REPLACE THIS WITH YOUR ACTUAL SHODAN API KEY
    _  SHODAN_API_KEY = "YOUR_SHODAN_API_KEY_HERE"_
    ```

## 🚀 Usage

Because the script uses raw sockets for ARP scanning, it requires elevated privileges.

### Linux / macOS
```bash
    sudo python3 iot_scanner.py
Windows
Open Command Prompt or PowerShell as Administrator, then run:

Bash
    python iot_scanner.py
📊 Sample Output
Plaintext
[*] Scanning network range: 192.168.1.1/24 ...(IP ADDRESS)
[+] Found 4 devices.

============================================================
IOT VULNERABILITY REPORT
============================================================
"Here you will get the results ":
 [DEVICE] IP: 192.168.1.102 | MAC: 7C:K2:91:88:77:66
         Vendor: TP-Link
         [!] RISK: Possible Default Credentials found!
             User: admin / Pass: admin


⚠️ Ethical Disclaimer
This tool is for educational and defensive purposes only.

Do not scan networks you do not own or do not have explicit permission to audit.

Unauthorized network scanning can be considered a cybercrime in many jurisdictions.

The developers assume no liability for misuse of this software.

🤝 Contributing
Contributions are welcome! Please open an issue or submit a pull request for any bugs or feature enhancements.
