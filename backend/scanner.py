import nmap
import json
from flask import Flask, request, jsonify
from flask_cors import CORS
import sys
import socket
import re
from threading import Thread
import time
import requests
from datetime import datetime, timedelta

app = Flask(__name__)
CORS(app, resources={
    r"/api/*": {
        "origins": "*",
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
    }
})

# Cache CVEs to avoid hitting API limits
CVE_CACHE = {}
CACHE_EXPIRY = timedelta(hours=24)

CVE_DATABASE = {
    # Exact version matches
    'OpenSSH 6.6.1p1': [
        {'id': 'CVE-2016-0777', 'severity': 'high', 
         'description': 'Information disclosure vulnerability'}
    ],
    'Apache httpd 2.4.7': [
        {'id': 'CVE-2017-15710', 'severity': 'medium', 
         'description': 'Out of bounds write vulnerability'},
        {'id': 'CVE-2017-7679', 'severity': 'high',
         'description': 'Buffer over-read vulnerability'}
    ],
    'OpenSSH 7.4': [
        {'id': 'CVE-2018-15473', 'severity': 'medium', 
         'description': 'Username enumeration vulnerability'}
    ],
    'Apache 2.4.41': [
        {'id': 'CVE-2021-44790', 'severity': 'critical', 
         'description': 'Buffer overflow in mod_lua'},
        {'id': 'CVE-2021-26691', 'severity': 'high', 
         'description': 'Heap overflow in mod_session'}
    ],
    'MySQL 5.7.31': [
        {'id': 'CVE-2021-2154', 'severity': 'high', 
         'description': 'Denial of Service vulnerability'}
    ],
    'nginx 1.18.0': [
        {'id': 'CVE-2021-23017', 'severity': 'high', 
         'description': '1-byte memory overwrite in resolver'}
    ],
    
    # Generic product matches (catches all versions)
    'Apache httpd': [
        {'id': 'CVE-2021-44790', 'severity': 'high', 
         'description': 'Potential buffer overflow in mod_lua'},
        {'id': 'CVE-2021-26691', 'severity': 'medium',
         'description': 'Potential heap overflow in mod_session'}
    ],
    'nginx': [
        {'id': 'CVE-2021-23017', 'severity': 'medium', 
         'description': 'Potential resolver vulnerability'}
    ],
    'OpenSSH': [
        {'id': 'CVE-2018-15473', 'severity': 'low', 
         'description': 'Username enumeration in older versions'}
    ],
    'Microsoft IIS': [
        {'id': 'CVE-2017-7269', 'severity': 'critical',
         'description': 'Remote code execution via WebDAV'}
    ],
    'Microsoft-IIS': [
        {'id': 'CVE-2017-7269', 'severity': 'critical',
         'description': 'Remote code execution via WebDAV'}
    ],
    'Apache Tomcat': [
        {'id': 'CVE-2020-1938', 'severity': 'critical',
         'description': 'Ghostcat - AJP request injection'}
    ],
    'MySQL': [
        {'id': 'CVE-2021-2154', 'severity': 'medium',
         'description': 'Potential DoS vulnerability'}
    ],
    'PostgreSQL': [
        {'id': 'CVE-2021-32027', 'severity': 'high',
         'description': 'Buffer overflow vulnerability'}
    ],
    'vsftpd': [
        {'id': 'CVE-2011-2523', 'severity': 'critical',
         'description': 'Backdoor in version 2.3.4'}
    ],
    'ProFTPD': [
        {'id': 'CVE-2015-3306', 'severity': 'critical',
         'description': 'Remote code execution'}
    ],
    'Samba': [
        {'id': 'CVE-2017-7494', 'severity': 'critical',
         'description': 'Remote code execution (SambaCry)'}
    ],
    'Microsoft Windows RPC': [
        {'id': 'CVE-2003-0352', 'severity': 'critical',
         'description': 'Buffer overflow (MS03-026)'}
    ],
    'telnet': [
        {'id': 'CVE-2020-10188', 'severity': 'high',
         'description': 'Utility functions allow remote code execution'}
    ],
    'smtp': [
        {'id': 'CVE-2020-7247', 'severity': 'critical',
         'description': 'OpenSMTPD remote code execution'}
    ],
}

SCAN_TYPES = {
    'quick': '-Pn -T4 -sT',  # Fast scan, top 100 ports
    'intense': '-Pn -T4 -A -v',  # Full scan
    'stealth': '-sS -Pn -T2',  # Slow stealth
    'version': '-Pn -sV -T4',  # Version detection only
    'ping': '-sn',  # Host discovery
    'udp': '-sU -Pn -T4 --top-ports 20',  # Top 20 UDP ports
    'aggressive': '-Pn -sV -T4',  # Fast version scan
    'dns': '-sL'  # DNS list
}

def fetch_cves_from_nvd(product_name, version=None):
    """Fetch CVEs from NVD API"""
    cache_key = f"{product_name}_{version}" if version else product_name
    
    # Check cache first
    if cache_key in CVE_CACHE:
        cached_data, timestamp = CVE_CACHE[cache_key]
        if datetime.now() - timestamp < CACHE_EXPIRY:
            return cached_data
    
    try:
        # NVD API v2.0
        base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        
        # Build search query
        if version:
            keyword = f"{product_name} {version}"
        else:
            keyword = product_name
        
        params = {
            'keywordSearch': keyword,
            'resultsPerPage': 10  # Limit results
        }
        
        response = requests.get(base_url, params=params, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            vulnerabilities = data.get('vulnerabilities', [])
            cves = []
            
            for vuln in vulnerabilities[:5]:  # Limit to top 5
                cve_data = vuln.get('cve', {})
                cve_id = cve_data.get('id', 'Unknown')
                
                # Get severity from CVSS v3 or v2
                metrics = cve_data.get('metrics', {})
                severity = 'unknown'
                
                if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                    severity = metrics['cvssMetricV31'][0]['cvssData']['baseSeverity'].lower()
                elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                    score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
                    if score >= 7.0:
                        severity = 'high'
                    elif score >= 4.0:
                        severity = 'medium'
                    else:
                        severity = 'low'
                
                # Get description
                descriptions = cve_data.get('descriptions', [])
                description = 'No description available'
                if descriptions:
                    description = descriptions[0].get('value', 'No description')
                    # Truncate long descriptions
                    if len(description) > 100:
                        description = description[:97] + '...'
                
                cves.append({
                    'id': cve_id,
                    'severity': severity,
                    'description': description
                })
            
            # Cache the results
            CVE_CACHE[cache_key] = (cves, datetime.now())
            return cves
        else:
            print(f"NVD API error: {response.status_code}", file=sys.stderr)
            return []
    
    except Exception as e:
        print(f"Error fetching CVEs from NVD: {str(e)}", file=sys.stderr)
        return []

def is_domain(target):
    return bool(re.search('[a-zA-Z]', target))

def resolve_domain(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

@app.route('/api/scan', methods=['POST', 'OPTIONS'])
def scan_network():
    if request.method == 'OPTIONS':
        return '', 204
    
    data = request.json
    target = data.get('target', '').strip() 
    
    
    target = re.sub(r'^https?://', '', target) 
    target = target.rstrip('/')  
    
    port_range = data.get('portRange', '1-1000')
    scan_type = data.get('scanType', 'quick')
    use_live_cve = data.get('useLiveCVE', False)
    
    if not target:
        return jsonify({'error': 'No target specified'}), 400
    
    scan_args = SCAN_TYPES.get(scan_type, '-Pn -T4 -sT')
    
    
    original_target = target
    if is_domain(target):
        target_ip = resolve_domain(target)
        if not target_ip:
            return jsonify({'error': f'Could not resolve domain: {target}'}), 400
    else:
        target_ip = target
    
    
    
    print(f"\n{'='*60}", file=sys.stderr)
    print(f"🎯 SCAN STARTED", file=sys.stderr)
    print(f"Target: {original_target} → {target_ip}", file=sys.stderr)
    print(f"Ports: {port_range}", file=sys.stderr)
    print(f"Type: {scan_type} | Args: {scan_args}", file=sys.stderr)
    print(f"Live CVE: {'✅ ENABLED' if use_live_cve else '❌ DISABLED'}", file=sys.stderr)
    print(f"{'='*60}\n", file=sys.stderr)
    sys.stderr.flush()
    
    try:
        nm = nmap.PortScanner()
        
        # Run scan
        start_time = time.time()
        if scan_type in ['ping', 'dns']:
            nm.scan(hosts=target_ip, arguments=scan_args)
        else:
            nm.scan(hosts=target_ip, ports=port_range, arguments=scan_args)
        
        elapsed = time.time() - start_time
        print(f"⏱️  Scan completed in {elapsed:.2f}s", file=sys.stderr)
        
        # Parse results
        all_hosts = nm.all_hosts()
        if not all_hosts:
            print("⚠️  No hosts found", file=sys.stderr)
            return jsonify([])
        
        results = []
        for host in all_hosts:
            print(f"\n📍 Host: {host} [{nm[host].state()}]", file=sys.stderr)
            
            # Get hostname
            try:
                hostname = socket.gethostbyaddr(host)[0]
            except:
                hostname = nm[host].hostname() or (original_target if is_domain(original_target) else 'Unknown')
            
            host_data = {
                'ip': host,
                'hostname': hostname,
                'status': nm[host].state(),
                'ports': [],
                'vulnerabilities': []
            }
            
            if is_domain(original_target):
                host_data['domain'] = original_target
            
            # OS detection
            if 'osmatch' in nm[host] and nm[host]['osmatch']:
                os_name = nm[host]['osmatch'][0]['name']
                host_data['os'] = os_name
                print(f"   OS: {os_name}", file=sys.stderr)
            
            # Skip port details for ping/DNS scans
            if scan_type in ['ping', 'dns']:
                results.append(host_data)
                continue
            
            # Process ports
            protocols = nm[host].all_protocols()
            if not protocols:
                print(f"   ⚠️  No open ports found", file=sys.stderr)
                results.append(host_data)
                continue
            
            for proto in protocols:
                ports = sorted(nm[host][proto].keys())
                print(f"   {proto.upper()}: {len(ports)} port(s) → {ports[:10]}{'...' if len(ports) > 10 else ''}", file=sys.stderr)
                
                for port in ports:
                    port_info = nm[host][proto][port]
                    
                    product = port_info.get('product', '')
                    version = port_info.get('version', '')
                    name = port_info.get('name', 'unknown')
                    state = port_info.get('state', 'unknown')
                    
                    # Build version string
                    if product and version:
                        service_version = f"{product} {version}"
                    elif product:
                        service_version = product
                    else:
                        service_version = name
                    
                    port_data = {
                        'port': port,
                        'protocol': proto,
                        'state': state,
                        'service': name,
                        'version': service_version
                    }
                    
                    host_data['ports'].append(port_data)
                    
                    # Check for vulnerabilities with multiple matching strategies
                    vuln_added = set()  # Track added CVE IDs to avoid duplicates
                    
                    # Strategy 1: Exact version match (e.g., "Apache httpd 2.4.7")
                    if service_version in CVE_DATABASE:
                        for vuln in CVE_DATABASE[service_version]:
                            if vuln['id'] not in vuln_added:
                                host_data['vulnerabilities'].append({
                                    **vuln,
                                    'port': port,
                                    'service': name
                                })
                                vuln_added.add(vuln['id'])
                                print(f"      🚨 {vuln['id']} ({vuln['severity']}) on port {port}", file=sys.stderr)
                    
                    # Strategy 2: Product name - check both static DB and live API
                    if product and product in CVE_DATABASE:
                        for vuln in CVE_DATABASE[product]:
                            if vuln['id'] not in vuln_added:
                                host_data['vulnerabilities'].append({
                                    **vuln,
                                    'port': port,
                                    'service': name
                                })
                                vuln_added.add(vuln['id'])
                                print(f"      🚨 {vuln['id']} ({vuln['severity']}) on port {port}", file=sys.stderr)
                    
                    # Also fetch live CVEs from NVD (only if enabled)
                    if use_live_cve and product:
                        live_cves = fetch_cves_from_nvd(product, version if version else None)
                        for vuln in live_cves:
                            if vuln['id'] not in vuln_added:
                                host_data['vulnerabilities'].append({
                                    **vuln,
                                    'port': port,
                                    'service': name
                                })
                                vuln_added.add(vuln['id'])
                                print(f"      🚨 [LIVE] {vuln['id']} ({vuln['severity']}) on port {port}", file=sys.stderr)
                    
                    # Strategy 3: Service name match (e.g., "http", "ssh")
                    if name and name in CVE_DATABASE:
                        for vuln in CVE_DATABASE[name]:
                            if vuln['id'] not in vuln_added:
                                host_data['vulnerabilities'].append({
                                    **vuln,
                                    'port': port,
                                    'service': name
                                })
                                vuln_added.add(vuln['id'])
                                print(f"      🚨 {vuln['id']} ({vuln['severity']}) on port {port}", file=sys.stderr)
            
            results.append(host_data)
        
        total_ports = sum(len(h['ports']) for h in results)
        total_vulns = sum(len(h['vulnerabilities']) for h in results)
        
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"✅ SCAN COMPLETE", file=sys.stderr)
        print(f"   Hosts: {len(results)} | Ports: {total_ports} | Vulnerabilities: {total_vulns}", file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)
        sys.stderr.flush()
        
        return jsonify(results)
    
    except Exception as e:
        print(f"\n{'='*60}", file=sys.stderr)
        print(f"❌ ERROR: {str(e)}", file=sys.stderr)
        import traceback
        traceback.print_exc(file=sys.stderr)
        print(f"{'='*60}\n", file=sys.stderr)
        sys.stderr.flush()
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'ok', 'message': 'Scanner API is running'})

if __name__ == '__main__':
    print("\n" + "="*60)
    print("  🛡️  Network Security Scanner API")
    print("  🌐 http://0.0.0.0:5001")
    print("  ⚡ Run with sudo for full capabilities")
    print("  ✅ Supports: IPs, domains, reverse DNS")
    print("  🔍 Live CVE detection via NVD API")
    print("="*60 + "\n")
    app.run(debug=True, port=5001, host='0.0.0.0', threaded=True)
