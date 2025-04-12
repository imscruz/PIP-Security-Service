import subprocess
import json
import os
import time
import requests
from colorama import init, Fore, Style
from packaging import version
from datetime import datetime, timedelta

init()

def get_safety_db():
    try:
        # Fetch from Safety DB
        safety_db = requests.get("https://raw.githubusercontent.com/pyupio/safety-db/refs/heads/master/data/insecure_full.json")
        return safety_db.json()
    except:
        return {}

def check_pypi_info(package_name):
    try:
        response = requests.get(f"https://pypi.org/pypi/{package_name}/json")
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

def get_nvd_vulnerabilities(package_name):
    try:
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={package_name}"
        response = requests.get(api_url)
        if response.status_code == 200:
            return response.json()
        return None
    except:
        return None

def check_exploit_db(package_name):
    try:
        url = f"https://www.exploit-db.com/search?q={package_name}"
        response = requests.get(url)
        return response.status_code == 200 and "exploit" in response.text.lower()
    except:
        return False

def analyze_package(package_name, version_str, safety_db):
    risk_level = "SAFE"
    reason = "This package is SAFE ❤️ "

    # Check NVD database
    nvd_data = get_nvd_vulnerabilities(package_name)
    if nvd_data and nvd_data.get('vulnerabilities'):
        recent_vulns = [v for v in nvd_data['vulnerabilities'] 
                       if v.get('published') and 
                       datetime.strptime(v['published'], "%Y-%m-%dT%H:%M:%S.%fZ") > datetime.now() - timedelta(days=365)]
        if recent_vulns:
            return "CRITICAL", f"Found {len(recent_vulns)} recent vulnerabilities in NVD database"

    # Check Exploit-DB
    if check_exploit_db(package_name):
        return "CRITICAL", "Found in Exploit-DB database"

    # Known critical patterns
    CRITICAL_PATTERNS = {
        'eval': 'Contains potentially dangerous eval functions',
        'exec': 'Contains potentially dangerous exec functions',
        'telnet': 'Uses insecure telnet protocol',
        'ftp': 'Uses insecure FTP protocol',
        'crypto': 'May contain outdated cryptographic methods',
        'zeroday': 'Known for zero-day vulnerabilities',
        'obfuscator': 'May contain obfuscated code'
    }

    for pattern, msg in CRITICAL_PATTERNS.items():
        if pattern in package_name.lower():
            return "CRITICAL", msg

    # Check PyPI info
    pypi_info = check_pypi_info(package_name)
    if pypi_info:
        project_urls = pypi_info['info'].get('project_urls', {})
        has_source = bool(pypi_info['info'].get('project_url') or 'Source' in project_urls)
        has_docs = bool(pypi_info['info'].get('documentation_url') or 'Documentation' in project_urls)
        
        if not has_source and not has_docs:
            risk_level = "HIGH"
            reason = "Missing both source code and documentation"
    else:
        risk_level = "HIGH"
        reason = "Package not found on PyPI"

    return risk_level, reason

def show_banner():
    os.system('title PIP Security Service')
    banner = f"""
{Fore.RED}╔══════════════════════════════════════════════════════════════╗
║                PIP Security Package Checker                  ║
║                    Created by @imscruz                       ║
║----------------------------------------------------------    ║
║  🔒 Checks NVD Database for vulnerabilities                  ║
║  ⚠️  Scans Exploit-DB for known exploits                     ║
║  🛡️  Analyzes CWE patterns and security status               ║
║  💀 Identifies critical security issues                      ║
╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def clear_screen():
    os.system('cls' if os.name == 'nt' else 'clear')

def show_banner():
    banner = f"""
{Fore.RED}╔═══════════════════════════════════════════╗
║             PIP'SS Checking               ║
║          Created by @imscruz              ║
╚═══════════════════════════════════════════╝{Style.RESET_ALL}
"""
    print(banner)

def get_installed_packages():
    result = subprocess.run(['pip', 'list', '--format=json'], capture_output=True, text=True)
    return json.loads(result.stdout)

def check_package_security():
    print("Fetching security database...(0 / 4)")
    safety_db = get_safety_db()
    packages = get_installed_packages()
    
    safe_found = []
    high_risk = []
    critical = []

    for package in packages:
        name = package['name']
        version_str = package['version']
        risk_level, reason = analyze_package(name, version_str, safety_db)
        
        if risk_level == "SAFE":
            safe_found.append((name, reason))
        elif risk_level == "HIGH":
            high_risk.append((name, reason))
        else:
            critical.append((name, reason))

    return safe_found, high_risk, critical

def remove_packages(packages):
    for package, _ in packages:
        subprocess.run(['pip', 'uninstall', '-y', package])

# Add this at the start of main_menu function
def main_menu():
    clear_screen()  # Clear screen when tool starts
    while True:
        clear_screen()
        show_banner()
        print(f"{Fore.GREEN}[1] Check Package Security")
        print(f"{Fore.BLUE}[2] About")
        print(f"{Fore.RED}[3] Exit{Style.RESET_ALL}")
        
        choice = input("\nSelect an option: ")

        if choice == '1':
            clear_screen()
            show_banner()
            print("Analyzing packages...\n")
            safe, high, critical = check_package_security()

            print(f"{Fore.GREEN}SAFE Packages:{Style.RESET_ALL}")
            for pkg, reason in safe:
                print(f"✓ {pkg}")

            print(f"\n{Fore.YELLOW}HIGH RISK Packages:{Style.RESET_ALL}")
            for pkg, reason in high:
                print(f"! {pkg} - {reason}")

            print(f"\n{Fore.RED}CRITICAL Packages:{Style.RESET_ALL}")
            for pkg, reason in critical:
                print(f"⚠ {pkg} - {reason}")

            if high or critical:
                choice = input("\nWould you like to remove CRITICAL packages? (y/n): ")
                if choice.lower() == 'y':
                    remove_packages(critical)
                    print("\nPackages removed successfully!")
                    time.sleep(2)

            input("\nPress Enter to continue...")

        elif choice == '2':
            clear_screen()
            show_banner()
            print("Created by: @imscruz")
            print("Version: 1.1")
            print("A tool to check and manage pip package security levels")
            input("\nPress Enter to continue...")

        elif choice == '3':
            clear_screen()
            print("Goodbye!")
            break

if __name__ == "__main__":
    main_menu()