import nmap
import json
import re

def is_valid_target(target):
    if not target:
        return False
    tokens = target.split()
    for token in tokens:
        if token.startswith('-'):
            return False
        if not re.fullmatch(r'[a-zA-Z0-9.:/,\-]+', token):
            return False
    return True


def get_outbound_local_ip():
    """Find the local IP of the network interface used for active outbound routing."""
    try:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(('8.8.8.8', 80))
            return s.getsockname()[0]
    except Exception:
        return None


def get_system_default_gateway():
    """
    Detect the local system's default gateway IP address, interface, and metric.
    Works across Windows and Linux.
    Handles multiple adapters (Wi-Fi, Ethernet, VPN, VMware/WSL) by selecting
    the lowest-metric route bound to the active outbound interface.
    Returns: dict with {'ip': gateway_ip, 'interface': interface_ip, 'metric': metric, 'mac': mac, 'mac_vendor': vendor} or None
    """
    try:
        import platform
        import subprocess
        import re

        system = platform.system().lower()
        active_local_ip = get_outbound_local_ip()

        if 'windows' in system:
            cmd = ['cmd', '/c', 'route', 'print', '0.0.0.0']
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=4).decode('latin-1', errors='ignore')
            candidates = []
            for line in output.splitlines():
                parts = line.strip().split()
                # Windows route table row:
                # Destination Netmask Gateway Interface Metric
                # 0.0.0.0     0.0.0.0 192.168.1.1 192.168.1.41 30
                if len(parts) >= 5 and parts[0] == '0.0.0.0' and parts[1] == '0.0.0.0':
                    gw_ip = parts[2]
                    iface_ip = parts[3]
                    try:
                        metric = int(parts[4])
                    except (ValueError, IndexError):
                        metric = 9999

                    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', gw_ip) and gw_ip != '0.0.0.0':
                        is_active = bool(active_local_ip and iface_ip == active_local_ip)
                        candidates.append({
                            'ip': gw_ip,
                            'interface': iface_ip,
                            'metric': metric,
                            'is_active': is_active
                        })

            if candidates:
                # Prioritize active outbound interface, then lowest metric
                candidates.sort(key=lambda c: (not c['is_active'], c['metric']))
                best = candidates[0]
                gw_ip = best['ip']
                iface_ip = best['interface']
                metric = best['metric']

                # Try to retrieve MAC address from system ARP table
                gw_mac = ''
                try:
                    arp_out = subprocess.check_output(['arp', '-a', gw_ip], stderr=subprocess.DEVNULL, timeout=2).decode('latin-1', errors='ignore')
                    m_mac = re.search(r'([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})', arp_out)
                    if m_mac:
                        gw_mac = m_mac.group(1).replace('-', ':').lower()
                except Exception:
                    pass

                return {
                    'ip': gw_ip,
                    'interface': iface_ip,
                    'metric': metric,
                    'mac': gw_mac,
                    'mac_vendor': ''
                }

        else:
            # Linux: parse 'ip route show default'
            cmd = ['ip', 'route', 'show', 'default']
            output = subprocess.check_output(cmd, stderr=subprocess.DEVNULL, timeout=4).decode('utf-8', errors='ignore')
            candidates = []
            for line in output.splitlines():
                m = re.search(r'default\s+via\s+(\d{1,3}(?:\.\d{1,3}){3})(?:\s+dev\s+(\S+))?(?:.*metric\s+(\d+))?', line)
                if m:
                    gw_ip = m.group(1)
                    dev = m.group(2) or ''
                    metric = int(m.group(3)) if m.group(3) else 100
                    candidates.append({'ip': gw_ip, 'interface': dev, 'metric': metric})

            if candidates:
                candidates.sort(key=lambda c: c['metric'])
                best = candidates[0]
                gw_ip = best['ip']

                gw_mac = ''
                try:
                    with open('/proc/net/arp', 'r') as f:
                        for row in f:
                            rp = row.split()
                            if len(rp) >= 4 and rp[0] == gw_ip:
                                gw_mac = rp[3].lower()
                                break
                except Exception:
                    pass

                return {
                    'ip': gw_ip,
                    'interface': best['interface'],
                    'metric': best['metric'],
                    'mac': gw_mac,
                    'mac_vendor': ''
                }
    except Exception:
        pass
    return None


def run_network_scan(target_ip, scan_type='discovery', custom_args=None):
    if not is_valid_target(target_ip):
        return json.dumps([{"error": "Invalid target specified."}])

    nm = nmap.PortScanner()
    scan_results = []

    try:
        if scan_type == 'discovery':
            nm.scan(hosts=target_ip, arguments='-sn')

            for host in nm.all_hosts():
                if nm[host].state() == 'up':
                    mac_address = nm[host]['addresses'].get('mac', 'Unknown')
                    mac_vendor = nm[host].get('vendor', {}).get(mac_address, '')
                    scan_results.append({
                        'ip': host,
                        'status': 'up',
                        'mac': mac_address,
                        'mac_vendor': mac_vendor
                    })

            # Check if local default gateway was missed because it drops ICMP ping
            sys_gw = get_system_default_gateway()
            if sys_gw and sys_gw.get('ip'):
                gw_ip = sys_gw['ip']
                found_ips = {r['ip'] for r in scan_results}
                if gw_ip not in found_ips:
                    in_target = False
                    try:
                        import ipaddress
                        if '/' in target_ip:
                            in_target = ipaddress.ip_address(gw_ip) in ipaddress.ip_network(target_ip, strict=False)
                        elif '-' in target_ip:
                            base = target_ip.split('-')[0].rsplit('.', 1)[0]
                            in_target = gw_ip.startswith(base + '.')
                        elif target_ip == gw_ip:
                            in_target = True
                    except Exception:
                        pass

                    if in_target:
                        try:
                            gw_nm = nmap.PortScanner()
                            gw_nm.scan(hosts=gw_ip, arguments='-Pn -p 53,80,443,8080 --open')
                            if gw_ip in gw_nm.all_hosts() and gw_nm[gw_ip].state() == 'up':
                                mac_addr = gw_nm[gw_ip]['addresses'].get('mac', sys_gw.get('mac') or 'Unknown')
                                mac_vndr = gw_nm[gw_ip].get('vendor', {}).get(mac_addr, sys_gw.get('mac_vendor') or '')
                                scan_results.append({
                                    'ip': gw_ip,
                                    'status': 'up',
                                    'mac': mac_addr,
                                    'mac_vendor': mac_vndr,
                                    'stealth_gateway': True
                                })
                        except Exception:
                            pass
        elif scan_type == 'fast_scan':
            # ใช้ -sV เพื่อดึงเวอร์ชันของ Service และ -O ตรวจ OS
            nm.scan(hosts=target_ip, arguments='-F -sV --version-intensity 7 -O')

            for host in nm.all_hosts():
                ports = []

                if nm[host].all_protocols():
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            port_data = nm[host][proto][port]

                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            extrainfo = port_data.get('extrainfo', '')

                            full_version = f"{product} {version} {extrainfo}".strip()
                            if not full_version:
                                full_version = "Unknown Version"

                            ports.append({
                                'port': port,
                                'protocol': proto,
                                'state': port_data.get('state'),
                                'name': port_data.get('name'),
                                'version_info': full_version
                            })

                os_info = 'Unknown'
                if nm[host].get('osmatch'):
                    os_info = nm[host]['osmatch'][0]['name']

                mac_address = nm[host]['addresses'].get('mac', 'Unknown')
                mac_vendor = nm[host].get('vendor', {}).get(mac_address, '')

                scan_results.append({
                    'ip': host,
                    'os': os_info,
                    'mac': mac_address,
                    'mac_vendor': mac_vendor,
                    'ports': ports
                })

        elif scan_type == 'intense':
            # Intense Scan: -T4 -A -v (OS, version, script, traceroute, aggressive timing)
            nm.scan(hosts=target_ip, arguments='-T4 -A -v')

            for host in nm.all_hosts():
                if nm[host].state() != 'up':
                    continue
                ports = []

                if nm[host].all_protocols():
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            port_data = nm[host][proto][port]

                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            extrainfo = port_data.get('extrainfo', '')

                            full_version = f"{product} {version} {extrainfo}".strip()
                            if not full_version:
                                full_version = "Unknown Version"

                            ports.append({
                                'port': port,
                                'protocol': proto,
                                'state': port_data.get('state'),
                                'name': port_data.get('name'),
                                'version_info': full_version
                            })

                os_info = 'Unknown'
                if nm[host].get('osmatch'):
                    os_info = nm[host]['osmatch'][0]['name']

                mac_address = nm[host]['addresses'].get('mac', 'Unknown')
                mac_vendor = nm[host].get('vendor', {}).get(mac_address, '')

                trace_hops = []
                if 'trace' in nm[host] and 'hops' in nm[host]['trace']:
                    trace_hops = nm[host]['trace']['hops']
                scan_results.append({
                    'ip': host,
                    'os': os_info,
                    'mac': mac_address,
                    'mac_vendor': mac_vendor,
                    'ports': ports,
                    'trace_hops': trace_hops
                })

        elif scan_type == 'custom' and custom_args:
            # Custom nmap arguments — ผู้ใช้กำหนด args เอง
            # ใช้ Whitelist แทน Blacklist เพื่อความปลอดภัย
            import shlex

            # Whitelist เฉพาะ flags ที่ปลอดภัยและจำเป็น
            ALLOWED_FLAGS = {
                '-sV', '-sS', '-sT', '-sU', '-sN', '-sF', '-sX',  # Scan types
                '-F',                                                 # Fast scan
                '-p',                                                 # Port range
                '-T0', '-T1', '-T2', '-T3', '-T4',                  # Timing (ไม่อนุญาต T5)
                '--open',                                             # แสดงเฉพาะ open ports
                '-O',                                                 # OS detection
                '--version-intensity',                                # Version intensity
                '-sC',                                                # Default scripts
                '--top-ports',                                        # Top N ports
            }

            try:
                tokens = shlex.split(custom_args)
            except ValueError as e:
                return json.dumps([{"error": f"Invalid arguments format: {str(e)}"}])

            validated_tokens = []
            i = 0
            while i < len(tokens):
                token = tokens[i]
                if token.startswith('-'):
                    # แยก flag ออกจาก value (กรณี --flag=value)
                    flag = token.split('=')[0]
                    if flag not in ALLOWED_FLAGS:
                        return json.dumps([{"error": f"Flag not allowed: {flag}. Allowed flags: {', '.join(sorted(ALLOWED_FLAGS))}"}])
                    # ตรวจว่า value ที่ตามมาไม่มี path หรือ special characters
                    validated_tokens.append(token)
                    # ถ้า flag นี้รับ value แยก (เช่น -p 80-443)
                    if '=' not in token and i + 1 < len(tokens) and not tokens[i + 1].startswith('-'):
                        next_val = tokens[i + 1]
                        # อนุญาตเฉพาะ alphanumeric, -, ,, * (สำหรับ port ranges)
                        if not re.fullmatch(r'[\w,\-\*]+', next_val):
                            return json.dumps([{"error": f"Invalid value for {flag}: {next_val}"}])
                        validated_tokens.append(next_val)
                        i += 1
                else:
                    return json.dumps([{"error": f"Unexpected token: {token}. All arguments must start with '-'"}])
                i += 1

            safe_args = ' '.join(validated_tokens)
            nm.scan(hosts=target_ip, arguments=safe_args)

            for host in nm.all_hosts():
                # แสดงเฉพาะ host ที่ state == 'up' เท่านั้น
                if nm[host].state() != 'up':
                    continue

                ports = []

                if nm[host].all_protocols():
                    for proto in nm[host].all_protocols():
                        for port in nm[host][proto].keys():
                            port_data = nm[host][proto][port]
                            product = port_data.get('product', '')
                            version = port_data.get('version', '')
                            extrainfo = port_data.get('extrainfo', '')
                            full_version = f"{product} {version} {extrainfo}".strip() or "Unknown Version"
                            ports.append({
                                'port': port,
                                'protocol': proto,
                                'state': port_data.get('state'),
                                'name': port_data.get('name'),
                                'version_info': full_version
                            })

                os_info = 'Unknown'
                if nm[host].get('osmatch'):
                    os_info = nm[host]['osmatch'][0]['name']

                mac_address = nm[host]['addresses'].get('mac', 'Unknown')
                mac_vendor = nm[host].get('vendor', {}).get(mac_address, '')

                scan_results.append({
                    'ip': host,
                    'os': os_info,
                    'mac': mac_address,
                    'mac_vendor': mac_vendor,
                    'ports': ports,
                    'custom_args': safe_args
                })

        if not scan_results:
            return json.dumps([{"error": "Scan completed but no hosts found. The target may be offline, or the arguments may not have produced results (e.g. missing -sn for discovery or -p for port scan)."}])

        return json.dumps(scan_results)

    except Exception as e:
        return json.dumps([{"error": str(e)}])


def lookup_cves_nvd(product, version, max_results=5):
    """Query NVD API for CVEs matching a product/version string."""
    import urllib.request
    import urllib.parse

    NVD_API_KEY = "b92e0f90-6616-404b-a76e-14e29597d524"

    if not product or product.strip() == '':
        return []

    keyword = f"{product} {version}".strip()
    params = urllib.parse.urlencode({
        'keywordSearch': keyword,
        'resultsPerPage': max_results,
    })
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{params}"

    try:
        req = urllib.request.Request(url, headers={
            'apiKey': NVD_API_KEY,
            'User-Agent': 'NetworkScanner/1.0'
        })
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        cves = []
        for vuln in data.get('vulnerabilities', []):
            cve_item = vuln.get('cve', {})
            cve_id = cve_item.get('id', '')
            # Description (English preferred)
            descs = cve_item.get('descriptions', [])
            description = next((d['value'] for d in descs if d.get('lang') == 'en'), '')

            # CVSS score and severity (try v31, then v30, then v2)
            metrics = cve_item.get('metrics', {})
            cvss_score = None
            severity = 'UNKNOWN'
            for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
                if key in metrics and metrics[key]:
                    m = metrics[key][0]
                    cvss_data = m.get('cvssData', {})
                    cvss_score = cvss_data.get('baseScore')
                    severity = m.get('baseSeverity', cvss_data.get('baseSeverity', 'UNKNOWN'))
                    break

            # CWE name from weaknesses (ชื่อหมวดหมู่ช่องโหว่)
            CWE_NAMES = {
                'CWE-20':  'Improper Input Validation',
                'CWE-22':  'Path Traversal',
                'CWE-74':  'Injection',
                'CWE-77':  'Command Injection',
                'CWE-78':  'OS Command Injection',
                'CWE-79':  'Cross-Site Scripting (XSS)',
                'CWE-89':  'SQL Injection',
                'CWE-94':  'Code Injection',
                'CWE-119': 'Buffer Overflow',
                'CWE-120': 'Buffer Copy Without Checking Size',
                'CWE-121': 'Stack-Based Buffer Overflow',
                'CWE-122': 'Heap-Based Buffer Overflow',
                'CWE-125': 'Out-of-Bounds Read',
                'CWE-134': 'Format String Vulnerability',
                'CWE-189': 'Numeric Errors',
                'CWE-190': 'Integer Overflow',
                'CWE-191': 'Integer Underflow',
                'CWE-200': 'Information Exposure',
                'CWE-255': 'Credentials Management',
                'CWE-264': 'Permissions & Privileges',
                'CWE-269': 'Improper Privilege Management',
                'CWE-287': 'Improper Authentication',
                'CWE-294': 'Authentication Bypass',
                'CWE-295': 'Certificate Validation',
                'CWE-310': 'Cryptographic Issues',
                'CWE-320': 'Key Management Errors',
                'CWE-326': 'Inadequate Encryption Strength',
                'CWE-327': 'Broken/Risky Crypto',
                'CWE-330': 'Weak Randomness',
                'CWE-352': 'Cross-Site Request Forgery (CSRF)',
                'CWE-362': 'Race Condition',
                'CWE-369': 'Divide By Zero',
                'CWE-400': 'Uncontrolled Resource Consumption',
                'CWE-401': 'Memory Leak',
                'CWE-404': 'Improper Resource Shutdown',
                'CWE-416': 'Use After Free',
                'CWE-434': 'Unrestricted File Upload',
                'CWE-476': 'NULL Pointer Dereference',
                'CWE-502': 'Deserialization of Untrusted Data',
                'CWE-601': 'Open Redirect',
                'CWE-611': 'XML External Entity (XXE)',
                'CWE-668': 'Exposure of Resource',
                'CWE-674': 'Uncontrolled Recursion',
                'CWE-681': 'Incorrect Conversion',
                'CWE-693': 'Protection Mechanism Failure',
                'CWE-732': 'Incorrect Permission Assignment',
                'CWE-755': 'Improper Exception Handling',
                'CWE-787': 'Out-of-Bounds Write',
                'CWE-798': 'Hardcoded Credentials',
                'CWE-824': 'Uninitialized Pointer',
                'CWE-843': 'Type Confusion',
                'CWE-862': 'Missing Authorization',
                'CWE-863': 'Incorrect Authorization',
                'CWE-918': 'Server-Side Request Forgery (SSRF)',
                'CWE-noinfo': 'Unspecified Vulnerability',
                'NVD-CWE-noinfo': 'Unspecified Vulnerability',
                'NVD-CWE-Other': 'Other Vulnerability Type',
            }
            cwe_name = None
            weaknesses = cve_item.get('weaknesses', [])
            for w in weaknesses:
                for desc in w.get('description', []):
                    cwe_id = desc.get('value', '')
                    if cwe_id in CWE_NAMES:
                        cwe_name = CWE_NAMES[cwe_id]
                        break
                    elif cwe_id.startswith('CWE-'):
                        cwe_name = cwe_id  # fallback: show CWE ID itself
                        break
                if cwe_name:
                    break

            cves.append({
                'cve_id': cve_id,
                'description': description[:300] if description else '',
                'cvss_score': cvss_score,
                'severity': severity.upper() if severity else 'UNKNOWN',
                'cwe_name': cwe_name or '',
            })
        return cves
    except Exception:
        return []


def run_vuln_scan(target_ip):
    """
    Vulnerability Scan: nmap -sV -O to detect services + OS, then query NVD API for CVEs.
    Returns same structure as other scans but each port has a 'cves' list.
    """
    if not is_valid_target(target_ip):
        return json.dumps([{"error": "Invalid target specified."}])

    nm = nmap.PortScanner()
    scan_results = []

    try:
        nm.scan(hosts=target_ip, arguments=' -T4 -A -v ')

        for host in nm.all_hosts():
            if nm[host].state() != 'up':
                continue

            ports = []
            if nm[host].all_protocols():
                for proto in nm[host].all_protocols():
                    for port in nm[host][proto].keys():
                        port_data = nm[host][proto][port]
                        if port_data.get('state') != 'open':
                            continue

                        product = port_data.get('product', '')
                        version = port_data.get('version', '')
                        extrainfo = port_data.get('extrainfo', '')
                        full_version = f"{product} {version} {extrainfo}".strip() or "Unknown Version"

                        # Query NVD API for CVEs
                        cves = lookup_cves_nvd(product, version)

                        ports.append({
                            'port': port,
                            'protocol': proto,
                            'state': port_data.get('state'),
                            'name': port_data.get('name'),
                            'version_info': full_version,
                            'cves': cves,
                        })

            os_info = 'Unknown'
            if nm[host].get('osmatch'):
                os_info = nm[host]['osmatch'][0]['name']

            mac_address = nm[host]['addresses'].get('mac', 'Unknown')
            mac_vendor = nm[host].get('vendor', {}).get(mac_address, '')

            scan_results.append({
                'ip': host,
                'os': os_info,
                'mac': mac_address,
                'mac_vendor': mac_vendor,
                'ports': ports,
            })

        if not scan_results:
            return json.dumps([{"error": "No hosts found. The target may be offline or have no open ports."}])

        return json.dumps(scan_results)

    except Exception as e:
        return json.dumps([{"error": str(e)}])
