#!/usr/bin/env python3
"""
Windows-specific packet capture diagnostic
Run this as Administrator to test Windows packet capture
"""

import sys
import os
import platform
import subprocess
import time

def check_admin_privileges():
    """Check if running as Administrator"""
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        if is_admin:
            print("✓ Running as Administrator")
            return True
        else:
            print("✗ NOT running as Administrator")
            print("  Right-click Command Prompt → 'Run as Administrator'")
            return False
    except Exception as e:
        print(f"Could not check admin privileges: {e}")
        return False

def check_npcap_installation():
    """Check if Npcap is properly installed"""
    print("\nChecking Npcap installation...")
    
    # Check for Npcap directory
    npcap_paths = [
        r"C:\Program Files\Npcap",
        r"C:\Program Files (x86)\Npcap",
        r"C:\Windows\System32\Npcap"
    ]
    
    npcap_found = False
    for path in npcap_paths:
        if os.path.exists(path):
            print(f"✓ Found Npcap directory: {path}")
            npcap_found = True
            
            # Check for key files
            dll_file = os.path.join(path, "wpcap.dll")
            if os.path.exists(dll_file):
                print("✓ wpcap.dll found")
            else:
                print("✗ wpcap.dll not found - reinstall with WinPcap compatibility")
            break
    
    if not npcap_found:
        print("✗ Npcap not found")
        print("  Download from: https://nmap.org/npcap/")
        print("  IMPORTANT: Check 'Install Npcap in WinPcap API-compatible Mode'")
        return False
    
    return True

def check_winpcap_service():
    """Check if NPF service is running"""
    print("\nChecking NPF service...")
    try:
        result = subprocess.run(['sc', 'query', 'npf'], 
                              capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            if "RUNNING" in result.stdout:
                print("✓ NPF service is running")
                return True
            else:
                print("✗ NPF service not running")
                print("  Try: net start npf")
                return False
        else:
            print("✗ NPF service not found")
            return False
    except Exception as e:
        print(f"Could not check NPF service: {e}")
        return False

def test_scapy_windows():
    """Test Scapy specifically on Windows"""
    print("\nTesting Scapy on Windows...")
    
    try:
        from scapy.all import sniff, get_if_list, conf
        print("✓ Scapy imported successfully")
        
        # Get interfaces
        interfaces = get_if_list()
        print(f"✓ Available interfaces: {len(interfaces)}")
        for i, iface in enumerate(interfaces[:5]):  # Show first 5
            print(f"  {i+1}. {iface}")
        
        # Test with different configurations
        print("\nTesting packet capture configurations...")
        
        configs = [
            {"name": "Default", "args": {}},
            {"name": "No promiscuous mode", "args": {"promisc": False}},
            {"name": "With timeout", "args": {"timeout": 3}},
            {"name": "Specific interface", "args": {"iface": interfaces[0] if interfaces else None}},
        ]
        
        for config in configs:
            if config["args"].get("iface") is None and "iface" in config["args"]:
                continue
                
            print(f"\n  Testing {config['name']}...")
            packets_captured = []
            
            def test_handler(pkt):
                packets_captured.append(pkt)
                print(f"    Captured: {pkt.summary()[:50]}...")
                if len(packets_captured) >= 3:
                    return True
            
            try:
                sniff(prn=test_handler, count=3, timeout=5, store=False, **config["args"])
                print(f"    Result: {len(packets_captured)} packets")
                
                if len(packets_captured) > 0:
                    print(f"✓ SUCCESS with {config['name']} configuration!")
                    return True
                    
            except Exception as e:
                print(f"    Failed: {e}")
        
        print("\n✗ All configurations failed")
        return False
        
    except ImportError as e:
        print(f"✗ Scapy import failed: {e}")
        return False
    except Exception as e:
        print(f"✗ Scapy test failed: {e}")
        return False

def check_windows_firewall():
    """Check Windows Firewall status"""
    print("\nChecking Windows Firewall...")
    try:
        result = subprocess.run(['netsh', 'advfirewall', 'show', 'allprofiles', 'state'], 
                              capture_output=True, text=True, shell=True)
        if result.returncode == 0:
            if "ON" in result.stdout:
                print("⚠ Windows Firewall is ON - this might block packet capture")
                print("  Consider temporarily disabling for testing")
            else:
                print("✓ Windows Firewall is OFF")
        else:
            print("Could not check Windows Firewall status")
    except Exception as e:
        print(f"Error checking firewall: {e}")

def print_windows_solutions():
    """Print Windows-specific solutions"""
    print("\n" + "="*60)
    print("WINDOWS PACKET CAPTURE SOLUTIONS")
    print("="*60)
    
    print("\n1. INSTALL/REINSTALL NPCAP:")
    print("   - Download: https://nmap.org/npcap/")
    print("   - Run installer as Administrator")
    print("   - CHECK: 'Install Npcap in WinPcap API-compatible Mode'")
    print("   - Restart computer after installation")
    
    print("\n2. START NPF SERVICE:")
    print("   - Open Command Prompt as Administrator")
    print("   - Run: net start npf")
    print("   - Or: sc start npf")
    
    print("\n3. DISABLE ANTIVIRUS TEMPORARILY:")
    print("   - Windows Defender: Settings → Virus & threat protection")
    print("   - Turn off Real-time protection temporarily")
    print("   - Add Python to exclusions")
    
    print("\n4. CHECK NETWORK ADAPTER:")
    print("   - Device Manager → Network adapters")
    print("   - Update network adapter drivers")
    print("   - Try different network interface")
    
    print("\n5. ALTERNATIVE METHODS:")
    print("   - Try running on WSL (Windows Subsystem for Linux)")
    print("   - Use Wireshark to verify packet capture works")
    print("   - Try with VPN disconnected")

def main():
    print("="*60)
    print("WINDOWS PACKET CAPTURE DIAGNOSTIC")
    print("="*60)
    
    if platform.system() != "Windows":
        print("This script is for Windows only!")
        sys.exit(1)
    
    print("Run this script and generate network traffic:")
    print("- Browse websites")
    print("- Run: ping google.com")
    print("- Download files")
    print("-" * 60)
    
    issues_found = 0
    
    # Check 1: Admin privileges
    if not check_admin_privileges():
        issues_found += 1
    
    # Check 2: Npcap installation
    if not check_npcap_installation():
        issues_found += 1
    
    # Check 3: NPF service
    if not check_winpcap_service():
        issues_found += 1
    
    # Check 4: Windows Firewall
    check_windows_firewall()
    
    # Check 5: Test actual capture
    print("\n" + "="*60)
    print("TESTING PACKET CAPTURE (Generate network traffic now!)")
    print("="*60)
    
    if not test_scapy_windows():
        issues_found += 1
    
    # Summary
    print("\n" + "="*60)
    print("DIAGNOSTIC COMPLETE")
    print("="*60)
    
    if issues_found == 0:
        print("✓ All checks passed! Packet capture should work.")
    else:
        print(f"✗ Found {issues_found} issues")
        print_windows_solutions()

if __name__ == "__main__":
    main()