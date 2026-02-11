# 🛡️ Network Security Scanner

A powerful web-based network security scanner with real-time vulnerability detection. Built with React frontend and Python Flask backend, featuring integration with the National Vulnerability Database (NVD) API for up-to-date CVE information.

![Network Scanner](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)
![React](https://img.shields.io/badge/React-18+-61dafb.svg)
![Nmap](https://img.shields.io/badge/Nmap-Required-red.svg)

## ✨ Features

### 🔍 Comprehensive Scanning
- **Multiple Scan Types**: Quick, Intense, Stealth, Version Detection, Ping, UDP, Aggressive, and Reverse DNS scans
- **Flexible Targets**: Supports IP addresses, IP ranges (CIDR), and domain names
- **Custom Port Ranges**: Scan specific ports or ranges (e.g., `1-1000`, `80,443,8080`)
- **Service Detection**: Identifies running services and their versions

### 🚨 Vulnerability Detection
- **Dual-Source CVE Database**: 
  - Static CVE database for offline/fast scanning
  - Live NVD API integration for real-time vulnerability data
- **Smart Caching**: 24-hour cache to preserve API rate limits
- **Multi-Strategy Matching**: 
  - Exact version matching (e.g., "Apache httpd 2.4.7")
  - Product name matching (e.g., "Apache httpd")
  - Service name matching (e.g., "http", "ssh")
- **Severity Classification**: Critical, High, Medium, Low risk levels

### 🎨 Modern UI
- **Real-time Progress Tracking**: Visual progress bars during scans
- **Interactive Host Selection**: Click to view detailed port and vulnerability information
- **Severity-Based Color Coding**: Easy identification of critical issues
- **Live CVE Indicators**: Visual badges for vulnerabilities from NVD API
- **Responsive Design**: Works on desktop and mobile devices

### 🔧 Advanced Features
- **Domain Resolution**: Automatic DNS resolution for domain targets
- **Reverse DNS Lookup**: Identifies hostnames for IP addresses
- **OS Detection**: Attempts to identify target operating systems
- **CORS Support**: Enables frontend-backend communication
- **Error Handling**: Graceful fallbacks and detailed error messages

## 📋 Prerequisites

### System Requirements
- **Python 3.8+**
- **Node.js 14+** (for frontend development)
- **Nmap**: Must be installed on your system
- **sudo/root access**: Required for certain scan types (SYN scans, OS detection)

### Install Nmap

**macOS:**
```bash
brew install nmap
```

**Ubuntu/Debian:**
```bash
sudo apt-get update
sudo apt-get install nmap
```

**Windows:**
Download from [nmap.org](https://nmap.org/download.html)

## 🚀 Installation

### 1. Clone the Repository
```bash
git clone "url"
cd websc
```

### 2. Backend Setup

```bash
# Navigate to backend directory
cd backend

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install flask flask-cors python-nmap requests

# Or use requirements.txt
pip install -r requirements.txt
```

**requirements.txt:**
```txt
flask>=2.0.0
flask-cors>=3.0.0
python-nmap>=0.7.1
requests>=2.28.0
```

### 3. Frontend Setup

```bash
# Navigate to frontend directory
cd websc

# Install dependencies
npm install

# Required packages
npm install react lucide-react
```

## 🎮 Usage

### Starting the Backend

```bash
cd backend

# Run with sudo for full capabilities (recommended)
sudo python3 scanner.py

# Or without sudo (limited scan types)
python3 scanner.py
```

The API server will start on `http://localhost:5001`

### Starting the Frontend

```bash
cd websc

# Development mode
npm start

# The app will open at http://localhost:3000
```

### Running a Scan

1. **Enter Target**: 
   - IP address: `192.168.1.1`
   - CIDR range: `192.168.1.0/24`
   - Domain: `scanme.nmap.org`

2. **Set Port Range**: 
   - Common ports: `1-1000`
   - Specific ports: `80,443,8080`
   - All ports: `1-65535` (slow)

3. **Choose Scan Type**:
   - **Quick Scan**: Fast scan of common ports
   - **Version Detection**: Identifies service versions
   - **Intense Scan**: Full scan with OS detection
   - **Stealth Scan**: SYN scan (requires sudo)

4. **Toggle Live CVE** (optional):
   - ✅ **ON**: Fetches real-time CVEs from NVD API
   - ❌ **OFF**: Uses only static CVE database

5. **Click "Start Scan"**

## 📊 API Endpoints

### POST `/api/scan`
Performs network scan

**Request Body:**
```json
{
  "target": "192.168.1.100",
  "portRange": "1-1000",
  "scanType": "quick",
  "useLiveCVE": true
}
```

**Response:**
```json
[
  {
    "ip": "192.168.1.100",
    "hostname": "webserver.local",
    "status": "up",
    "os": "Linux 5.x",
    "ports": [
      {
        "port": 80,
        "protocol": "tcp",
        "state": "open",
        "service": "http",
        "version": "Apache httpd 2.4.41"
      }
    ],
    "vulnerabilities": [
      {
        "id": "CVE-2021-44790",
        "severity": "critical",
        "description": "Buffer overflow in mod_lua",
        "port": 80,
        "service": "http",
        "source": "LIVE"
      }
    ]
  }
]
```

### GET `/api/health`
Health check endpoint

**Response:**
```json
{
  "status": "ok",
  "message": "Scanner API is running"
}
```

## 🔐 Scan Types Explained

| Scan Type | Description | Speed | Stealth | Requires Sudo |
|-----------|-------------|-------|---------|---------------|
| **Quick** | Top 100 common ports | ⚡ Fast | Medium | No |
| **Intense** | Full scan + OS detection | 🐌 Slow | Low | Yes |
| **Stealth** | SYN scan, harder to detect | 🐢 Very Slow | ⭐ High | Yes |
| **Version** | Service version detection | ⚡ Fast | Medium | No |
| **Ping** | Host discovery only | ⚡⚡ Very Fast | High | No |
| **UDP** | Top 20 UDP ports | 🐌 Slow | Medium | Yes |
| **Aggressive** | Fast version + OS scan | 🚀 Medium | Low | Yes |
| **DNS** | Reverse DNS lookup | ⚡⚡ Very Fast | ⭐ Very High | No |

## 🗄️ CVE Database

### Static Database
The scanner includes a curated static CVE database with known vulnerabilities for:
- OpenSSH (various versions)
- Apache httpd
- nginx
- MySQL
- PostgreSQL
- Microsoft IIS
- Samba
- FTP servers (vsftpd, ProFTPD)
- And more...

### Live NVD API Integration
When enabled, fetches real-time vulnerability data from the National Vulnerability Database:
- **API Endpoint**: `https://services.nvd.nist.gov/rest/json/cves/2.0`
- **Caching**: 24-hour cache per product/version
- **Rate Limiting**: Automatic cache prevents excessive API calls
- **Fallback**: Uses static database if API fails

## ⚙️ Configuration

### Backend Configuration

Edit `scanner.py` to customize:

```python
# API Port
app.run(port=5001)

# Cache expiry time
CACHE_EXPIRY = timedelta(hours=24)  # Change to desired time

# NVD API results limit
'resultsPerPage': 10  # Adjust based on needs
```

### Adding Custom CVEs

Edit the `CVE_DATABASE` dictionary in `scanner.py`:

```python
CVE_DATABASE = {
    'YourProduct 1.0': [
        {
            'id': 'CVE-2024-XXXXX',
            'severity': 'critical',
            'description': 'Your vulnerability description'
        }
    ]
}
```

## 🛡️ Security & Legal

### ⚠️ Important Warnings

- **Only scan networks you own or have explicit permission to test**
- Unauthorized network scanning may be **illegal** in your jurisdiction
- Some scan types can be detected by intrusion detection systems (IDS)
- Aggressive scans may impact network performance

### Best Practices

1. **Start with less invasive scans** (Ping, Quick)
2. **Use Stealth scans** in monitored environments
3. **Scan during maintenance windows** for production systems
4. **Rate limit your scans** to avoid triggering IDS
5. **Document permissions** before scanning

### Responsible Disclosure

If you discover vulnerabilities:
1. Do not exploit them
2. Report to the system owner immediately
3. Follow responsible disclosure guidelines
4. Allow reasonable time for patching

## 🐛 Troubleshooting

### Common Issues

**"No module named 'nmap'"**
```bash
pip install python-nmap
```

**"Nmap is not installed"**
```bash
# Verify nmap installation
nmap --version

# Install if missing (see Prerequisites)
```

**"Permission denied" errors**
```bash
# Run with sudo for full capabilities
sudo python3 scanner.py
```

**"Could not resolve domain"**
- Check DNS settings
- Verify domain is valid
- Try using IP address instead

**"Scan failed" / No results**
- Verify target is reachable: `ping <target>`
- Check firewall rules
- Try a simpler scan type (Quick or Ping)
- Ensure backend is running on port 5001

**CORS errors in frontend**
- Verify backend is running
- Check CORS configuration in `scanner.py`
- Ensure frontend is using correct backend URL

### Debug Mode

Enable detailed logging:

```python
# In scanner.py
app.run(debug=True, port=5001)
```

Check backend logs for detailed scan information:
```bash
# Backend outputs detailed logs to stderr
# Look for 🎯, 📍, 🚨 indicators
```

## 📈 Performance Tips

1. **Narrow port ranges**: Scan only necessary ports
2. **Use Quick scan**: For initial reconnaissance
3. **Enable Live CVE selectively**: Only when needed to save API quota
4. **Scan during off-hours**: Reduces network impact
5. **Use CIDR carefully**: `/24` scans 256 hosts - may take time

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

### Areas for Contribution

- Additional CVE database entries
- New scan types
- Export functionality (PDF, CSV, JSON)
- Scan scheduling
- Email notifications
- Multi-target scanning
- Historical scan comparison

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- **Nmap**: The backbone of network scanning
- **NVD**: National Vulnerability Database for CVE data
- **NIST**: For maintaining the CVE/CPE standards
- **React & Tailwind**: For the beautiful UI framework
- **Flask**: For the lightweight backend framework

## 📞 Support

For issues, questions, or suggestions:

- **Issues**: Open a GitHub issue
- **Discussions**: Use GitHub Discussions
- **Security**: Report vulnerabilities privately to maintainers

## 🗺️ Roadmap

- [ ] Export scan results (PDF/CSV/JSON)
- [ ] Scheduled scans
- [ ] Scan history and comparison
- [ ] Email/webhook notifications
- [ ] Custom vulnerability plugins
- [ ] Multi-threading for faster scans
- [ ] Docker containerization
- [ ] Authentication and multi-user support
- [ ] Integration with Metasploit/OpenVAS
- [ ] Automated remediation suggestions

---

**Built with ❤️ for cybersecurity professionals and enthusiasts**

⚠️ **Remember: With great power comes great responsibility. Scan ethically!**