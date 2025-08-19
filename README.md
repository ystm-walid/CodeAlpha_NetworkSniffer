# CodeAlpha – Cyber Security Internship 🚀
## Task 1: Basic Network Sniffer (Python)

This repository contains my **CodeAlpha Cyber Security Internship Project – Basic Network Sniffer**.  
The project demonstrates how to capture and analyze network traffic packets using Python.

---

## 📌 Project Overview
The **Network Sniffer** is a Python-based tool that listens to live network traffic and extracts key information such as:
- Source & Destination IP addresses  
- Protocol types (TCP, UDP, ICMP, etc.)  
- Payload (data carried by the packets)  

It provides hands-on understanding of how **data flows in networks** and gives a foundation for **ethical hacking, penetration testing, and traffic analysis**.

---

## ⚡ Features
✔️ Capture live packets on the network interface  
✔️ Display **source/destination IPs**  
✔️ Identify protocols (TCP/UDP/ICMP)  
✔️ Extract and show packet **payloads**  
✔️ Lightweight and beginner-friendly  

---

## 🛠️ Tech Stack
- **Python 3**  
- **Scapy** library (for packet capturing)  
- **Kali Linux** (running in VMware)  
- **Metasploitable 2 & 3** (for generating test traffic)  

---

## 📂 Repository Structure

---

## 🚀 Installation & Setup

1. Update system and install Python:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```bash
   sudo pip3 install scapy
   ```bash
   git clone https://github.com/YourUsername/CodeAlpha_NetworkSniffer.git
   ```bash
   cd CodeAlpha_NetworkSniffer
   ```bash
   sudo python3 sniffer.py
