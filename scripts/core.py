#!/usr/bin/env python3
import winrm
import sys
import argparse
import getpass
import json

WINRM_PORT = 5985

def connect_and_collect_data(ip, username, password, timeout):
    """
    Connect to Windows machine and collect system information
    Returns a dictionary with collected data or None on failure
    """
    try:
        print(f"[INFO] Connecting to {ip}...")
        session = winrm.Session(
            target=f'http://{ip}:{WINRM_PORT}/wsman',
            auth=(username, password),
            transport='basic',
            operation_timeout_sec=timeout,
            read_timeout_sec=timeout + 30
        )
        
        print(f"[INFO] Connected! Collecting system data...")
        
        system_data = {
            'hostname': None,
            'os_info': {},
            'installed_software': [],
            'installed_patches': []
        }
        
        # 1. Get hostname
        print(f"[INFO] Getting hostname...")
        result = session.run_cmd('hostname')
        if result.status_code == 0:
            system_data['hostname'] = result.std_out.decode('utf-8').strip()
            print(f"[SUCCESS] Hostname: {system_data['hostname']}")
        else:
            print(f"[WARNING] Could not get hostname")
        
        # 2. Get OS information
        print(f"[INFO] Getting OS information...")
        os_query = "Get-WmiObject Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture | ConvertTo-Json"
        
        result = session.run_ps(os_query)
        if result.status_code == 0:
            try:
                output = result.std_out.decode('utf-8').strip()
                if output and output != "null":
                    system_data['os_info'] = json.loads(output)
                    caption = system_data['os_info'].get('Caption', 'Unknown')
                    build = system_data['os_info'].get('BuildNumber', 'Unknown')
                    print(f"[SUCCESS] OS: {caption} (Build: {build})")
                else:
                    print(f"[WARNING] No OS data returned")
            except json.JSONDecodeError as e:
                print(f"[WARNING] Could not parse OS data: {e}")
        else:
            print(f"[WARNING] OS query failed: {result.std_err.decode('utf-8')}")
        
        # 3. Get installed software (using the fast and comprehensive registry method)
        print(f"[INFO] Getting installed software...")
        
        # --- THIS IS THE FIXED PART ---
        software_query = """
        $software = @()
        $regPaths = @(
            'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*',
            'HKLM:\\SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*'
        )
        
        foreach ($path in $regPaths) {
            if (Test-Path $path) {
                Get-ItemProperty $path | Where-Object { $_.DisplayName -and !$_.SystemComponent } | ForEach-Object {
                    $software += [PSCustomObject]@{
                        Name = $_.DisplayName
                        Version = $_.DisplayVersion
                        Publisher = $_.Publisher
                    }
                }
            }
        }
        
        $software | Sort-Object Name -Unique | ConvertTo-Json
        """
        # --- END OF FIX ---

        result = session.run_ps(software_query)
        if result.status_code == 0:
            try:
                output = result.std_out.decode('utf-8').strip()
                if output and output != "null":
                    software_data = json.loads(output)
                    if isinstance(software_data, dict):
                        system_data['installed_software'] = [software_data]
                    elif isinstance(software_data, list):
                        system_data['installed_software'] = software_data
                    
                    print(f"[SUCCESS] Found {len(system_data['installed_software'])} installed programs")
                else:
                    print(f"[WARNING] No software data returned")
            except json.JSONDecodeError as e:
                print(f"[WARNING] Could not parse software data: {e}")
        else:
            print(f"[WARNING] Software query failed: {result.std_err.decode('utf-8')}")
        
        # 4. Get installed patches
        print(f"[INFO] Getting installed patches...")
        patch_query = "Get-HotFix | Select-Object HotFixID,Description,InstalledOn | ConvertTo-Json"
        
        result = session.run_ps(patch_query)
        if result.status_code == 0:
            try:
                output = result.std_out.decode('utf-8').strip()
                if output and output != "null":
                    patch_data = json.loads(output)
                    if isinstance(patch_data, dict):
                        system_data['installed_patches'] = [patch_data]
                    elif isinstance(patch_data, list):
                        system_data['installed_patches'] = patch_data
                    
                    print(f"[SUCCESS] Found {len(system_data['installed_patches'])} installed patches")
                else:
                    print(f"[WARNING] No patch data returned")
            except json.JSONDecodeError as e:
                print(f"[WARNING] Could not parse patch data: {e}")
        else:
            print(f"[WARNING] Patch query failed: {result.std_err.decode('utf-8')}")
        
        return system_data
        
    except Exception as e:
        print(f"[ERROR] An unexpected error occurred: {str(e)}")
        return None

def display_collected_data(data):
    """
    Display collected data in readable format
    """
    if not data:
        print("No data to display")
        return
    
    print("\n" + "="*60)
    print("WINSPECT SYSTEM INFORMATION REPORT")
    print("="*60)
    
    # Hostname and OS
    print(f"\n[HOST AND OS]")
    print(f"Computer Name: {data.get('hostname', 'Unknown')}")
    os_info = data.get('os_info', {})
    if os_info:
        print(f"OS Name: {os_info.get('Caption', 'Unknown')} (Build: {os_info.get('BuildNumber', 'Unknown')})")
        print(f"Architecture: {os_info.get('OSArchitecture', 'Unknown')}")
    else:
        print("No OS information available")
    
    # Installed Software
    print(f"\n[INSTALLED SOFTWARE]")
    software_list = data.get('installed_software', [])
    if software_list:
        print(f"Total Programs: {len(software_list)}")
        print(f"\nFirst 15 programs:")
        for i, software in enumerate(software_list[:15]):
            name = software.get('Name', 'Unknown')
            version = software.get('Version', 'No version')
            publisher = software.get('Publisher', 'Unknown publisher')
            print(f"  {i+1:2}. {name} (v{version}) - {publisher}")
        
        if len(software_list) > 15:
            print(f"  ... and {len(software_list) - 15} more programs")
    else:
        print("No software information available")
    
    # Installed Patches
    print(f"\n[INSTALLED PATCHES]")
    patch_list = data.get('installed_patches', [])
    if patch_list:
        print(f"Total Patches: {len(patch_list)}")
        print(f"\nFirst 15 patches:")
        for i, patch in enumerate(patch_list[:15]):
            hotfix_id = patch.get('HotFixID', 'Unknown')
            description = patch.get('Description', 'Unknown')
            installed_on = patch.get('InstalledOn', {}).get('DateTime', 'Unknown date')
            print(f"  {i+1:2}. {hotfix_id} - {description} ({installed_on.split(' ')[0]})")
        
        if len(patch_list) > 15:
            print(f"  ... and {len(patch_list) - 15} more patches")
    else:
        print("No patch information available")

def save_data_to_file(data, filename):
    """
    Save collected data to JSON file
    """
    try:
        with open(filename, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        return True
    except Exception as e:
        print(f"[ERROR] Could not save to {filename}: {e}")
        return False

def main():
    parser = argparse.ArgumentParser(
        description="WinSpect: Windows System Information Collection Tool",
        epilog="Example: python winspect.py 192.168.1.100 -u YourUser --save report.json"
    )
    parser.add_argument("target_ip", help="IP address of the Windows machine to scan")
    parser.add_argument("-u", "--username", required=True, help="Username for authentication (required)")
    parser.add_argument("--save", metavar="FILE", help="Save collected data to JSON file")
    parser.add_argument("--timeout", type=int, default=60, help="Timeout in seconds for operations (default: 60)")
    
    args = parser.parse_args()
    
    password = getpass.getpass(f"Enter password for {args.username}@{args.target_ip}: ")
    
    print("\nWINSPECT - Windows System Information Collection")
    print("-" * 50)
    
    system_data = connect_and_collect_data(args.target_ip, args.username, password, args.timeout)
    
    if system_data:
        display_collected_data(system_data)
        
        if args.save:
            if save_data_to_file(system_data, args.save):
                print(f"\n[INFO] Data saved to {args.save}")
        
        software_count = len(system_data.get('installed_software', []))
        patch_count = len(system_data.get('installed_patches', []))
        print(f"\n[SUCCESS] Data collection completed for {args.target_ip}")
        print(f"SUMMARY: {software_count} programs, {patch_count} patches collected")
        
    else:
        print(f"\n[FAILED] Could not collect data from {args.target_ip}")
        sys.exit(1)

if __name__ == "__main__":
    main()