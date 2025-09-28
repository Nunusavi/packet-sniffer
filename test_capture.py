#!/usr/bin/env python3
"""
Simple packet capture test script
Run this to verify if packet capture works on your system
"""

import sys
import time
from scapy.all import sniff, get_if_list, conf

def test_basic_capture():
    """Test basic packet capture functionality"""
    print("=" * 50)
    print("PACKET CAPTURE TEST")
    print("=" * 50)
    
    # Test 1: Import test
    print("✓ Scapy import successful")
    
    # Test 2: Interface detection
    try:
        interfaces = get_if_list()
        print(f"✓ Available interfaces: {interfaces}")
    except Exception as e:
        print(f"✗ Interface detection failed: {e}")
        return False
    
    # Test 3: Admin check
    import os
    import platform
    system = platform.system()
    
    is_admin = False
    try:
        if system == "Windows":
            import ctypes
            is_admin = ctypes.windll.shell32.IsUserAnAdmin()
        else:
            is_admin = os.geteuid() == 0
    except:
        pass
    
    if is_admin:
        print("✓ Running with admin/root privileges")
    else:
        print("✗ NOT running with admin/root privileges")
        print("  This is likely the main issue!")
    
    # Test 4: Simple capture test
    print("\n" + "=" * 50)
    print("STARTING 10-SECOND PACKET CAPTURE TEST")
    print("Try browsing to a website or run 'ping google.com'")
    print("=" * 50)
    
    packets_captured = 0
    
    def packet_handler(pkt):
        nonlocal packets_captured
        packets_captured += 1
        print(f"Packet {packets_captured}: {pkt.summary()}")
        if packets_captured >= 5:  # Stop after 5 packets
            return True
    
    try:
        # Try different capture methods
        methods = [
            ("Default capture", {}),
            ("IP filter only", {"filter": "ip"}),
            ("Promiscuous mode", {"promisc": True}),
        ]
        
        for method_name, kwargs in methods:
            print(f"\nTrying {method_name}...")
            try:
                sniff(prn=packet_handler, timeout=10, store=False, **kwargs)
                if packets_captured > 0:
                    break
            except Exception as e:
                print(f"  Failed: {e}")
                continue
        
        print(f"\n" + "=" * 50)
        print(f"RESULT: {packets_captured} packets captured")
        print("=" * 50)
        
        if packets_captured > 0:
            print("✓ SUCCESS: Packet capture is working!")
            return True
        else:
            print("✗ FAILED: No packets captured")
            print_troubleshooting_tips()
            return False
            
    except Exception as e:
        print(f"✗ Capture test failed: {e}")
        print_troubleshooting_tips()
        return False

def print_troubleshooting_tips():
    """Print troubleshooting tips"""
    print("\nTROUBLESHOOTING TIPS:")
    print("-" * 30)
    
    import platform
    system = platform.system()
    
    if system == "Windows":
        print("WINDOWS:")
        print("1. Run as Administrator (Right-click → 'Run as Administrator')")
        print("2. Install Npcap from https://nmap.org/npcap/")
        print("   - Check 'Install Npcap in WinPcap API-compatible Mode'")
        print("3. Disable antivirus temporarily")
        print("4. Check Windows Firewall settings")
        
    elif system == "Linux":
        print("LINUX:")
        print("1. Run with sudo: sudo python3 test_capture.py")
        print("2. Install libpcap: sudo apt-get install libpcap-dev")
        print("3. Add user to pcap group: sudo usermod -a -G pcap $USER")
        print("4. Check if interface is up: ip link show")
        
    elif system == "Darwin":  # macOS
        print("MACOS:")
        print("1. Run with sudo: sudo python3 test_capture.py")
        print("2. Install libpcap: brew install libpcap")
        print("3. Allow terminal in System Preferences → Security → Privacy")
        
    print("\nGENERAL:")
    print("- Try generating network traffic while testing")
    print("- Run: ping google.com (in another terminal)")
    print("- Check if you're on a restricted network")
    print("- Some corporate networks block packet capture")

def test_scapy_installation():
    """Test if scapy is properly installed"""
    print("\nTesting Scapy installation...")
    try:
        from scapy.all import IP, TCP, UDP, ICMP
        print("✓ Core scapy modules imported successfully")
        
        # Test packet creation
        test_pkt = IP()/TCP()
        print("✓ Packet creation works")
        
        return True
    except ImportError as e:
        print(f"✗ Scapy import failed: {e}")
        print("Install scapy: pip install scapy")
        return False
    except Exception as e:
        print(f"✗ Scapy test failed: {e}")
        return False

if __name__ == "__main__":
    print("Starting packet capture diagnostic...")
    
    if not test_scapy_installation():
        sys.exit(1)
    
    if test_basic_capture():
        print("\n🎉 Your system should work with the packet sniffer!")
    else:
        print("\n❌ Packet capture is not working on your system")
        print("Fix the issues above before running the main application")