### Network Traffic Monitor & Access Control
<img width="478" height="136" alt="изображение" src="https://github.com/user-attachments/assets/63a694dc-cad3-4154-b28d-d956073b5825" />

A C# console application for local network analysis, traffic monitoring, and device access control. This project demonstrates low-level network manipulation using raw sockets and the ARP protocol.
Disclaimer

This software is developed for educational purposes only. It is intended to demonstrate how network protocols (ARP, TCP/IP) work and how Man-in-the-Middle (MITM) attacks can be detected or performed. Use this tool only on networks you own or have explicit permission to test. The author assumes no responsibility for unauthorized use.
Key Features

    Network Scanning: Automatically scans the local subnet to map IP and MAC addresses of active devices.

    Traffic Monitoring: Calculates real-time Upload and Download speeds for specific targets.

    ARP Spoofing implementation: Reroutes traffic through the attacker's machine to analyze packets.

    Access Control: Ability to block internet access for specific devices (packet dropping/blackholing).

    Packet Manipulation: Automatic recalculation of TCP/UDP/IP checksums to ensure packet integrity during forwarding.

Technology Stack

    Language: C# (.NET 6/7/8)

    Libraries:

        SharpPcap (Wrapper for Npcap/LibPcap) for capturing and sending raw packets.

        PacketDotNet for parsing and modifying Ethernet, IP, TCP, and UDP headers.

    Architecture:

        Multithreaded architecture (separate threads for UI, Sniffing, and ARP Spoofing).

        Thread-safe collections (ConcurrentDictionary) for data management.

Technical Details

The application operates by manipulating the ARP cache of the target device and the gateway (router). It utilizes a Man-in-the-Middle (MITM) approach:

    Scanning: Broadcasts ARP requests to identify live hosts.

    Poisoning: Sends forged ARP responses to the victim (associating the Router's IP with the Attacker's MAC) and to the Router (associating the Victim's IP with the Attacker's MAC).

    Forwarding: Captures incoming traffic, modifies the destination MAC address, recalculates checksums (to prevent packet rejection), and forwards it to the intended recipient.

Requirements

    Windows OS.

    .NET Runtime installed.

    Npcap driver installed (ensure "Install Npcap in WinPcap API-compatible Mode" is checked during installation).

    Administrator privileges (required for raw socket access).

Usage

    Run the application as Administrator.

    Select the network interface for capturing.

    Wait for the network scan to complete.

    Select the Router ID and Target IDs.

    Use the command line interface to manage targets:

        block [ID] - Cut off internet access for the target.

        unblock [ID] - Restore access.
