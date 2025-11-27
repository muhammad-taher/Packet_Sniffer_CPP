Here is a clean, polished, professional **GitHub README.md** version of your content:

---

# 📡 Simple C++ Packet Sniffer

A lightweight and efficient **network packet sniffer** written in **C++** using the **libpcap** library.
This tool captures live network traffic and analyzes **Ethernet**, **IPv4**, **TCP**, and **ARP** packets, displaying essential information such as MAC addresses, IPs, ports, and protocol types.

---

## 🚀 Features

### 🔍 Device Enumeration

* Lists all available network interfaces on the system.

### 📥 Packet Capture

* Captures live packets from a selected network interface.
* Displays raw packet information in real-time.

### 🧩 Protocol Analysis

* **Ethernet**

  * Source & Destination MAC addresses
* **IPv4**

  * Source & Destination IP addresses
  * Protocol type
* **TCP**

  * Source & Destination ports
  * Detects and displays TCP traffic
* **ARP**

  * Detects ARP packets

---

## 📦 Prerequisites

Ensure the following are installed before running the tool:

* **G++ Compiler**
* **libpcap** (for packet capturing)

### Install Dependencies (Linux/Debian/Ubuntu)

```bash
sudo apt-get update
sudo apt-get install libpcap-dev
```

---

## 🛠️ Compilation

Compile using `g++` and link the **pcap** library:

```bash
g++ sniffer.cpp -o sniffer -lpcap
```

---

## ▶️ Usage

Run the executable with root privileges (required for device access):

```bash
sudo ./sniffer
```

### 1. Select Network Interface

When prompted, choose the interface number (e.g., `1` for `eth0` or `wlan0`).

### 2. View Captured Output

Packet details will be displayed in real-time.

---

## 📘 Example Output

```
Packet Captured at : Length : 66 bytes
Source Address : 00:1A:2B:3C:4D:5E
Destination Address : A1:B2:C3:D4:E5:F6
Type : IPv4
Source IP Address : 192.168.1.5
Destination IP Address : 142.250.1.1
Protocol : 6
Protocol : TCP
Source Port : 443
Destination Port : 55321
```

---

## 🧱 Code Structure

* `struct ethernet_header`
  Defines the Ethernet frame structure.

* `struct ip_header`
  Defines the IPv4 header fields.

* `struct tcp_header`
  Defines the TCP header fields.

* `packet_handler()`
  Callback function used with `pcap_loop` to process packets as they are captured.

---

## ⚠️ Disclaimer

This tool is intended **strictly for educational and diagnostic purposes**.
Do **not** capture or analyze network traffic without proper authorization.
Unauthorized packet sniffing may violate privacy laws and organizational policies.

---

If you want, I can also format this with badges, add screenshots, or create a more advanced README layout.
