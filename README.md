#  ARP/DNS Spoofing and SSL Stripping Tool

A network attack toolkit for performing **ARP poisoning**, **DNS spoofing**, and **SSL stripping** on local networks. The tool allows man-in-the-middle (MITM) control after successful ARP spoofing.

---

## Features

- ARP poisoning
- DNS spoofing 
- SSL stripping
- MITM position creation
- Passive network scan to identify active hosts
- Packet logging to `packet_log` file

---

## Requirements

- Python 3
- `scapy`

Install dependencies:
```bash
pip install scapy
```

---

## Usage

Run the main tool:
```bash
python funTimes.py
```

The tool will prompt you for an action:

### Main Options

- `scan` – Scan the network for active hosts
- `arp` – Perform ARP poisoning
- `mitm` – Enter MITM mode if already poisoned
- `quit` – Exit the tool

---

## 🔍 Functionality Details

### 1. **Scan**
- Enter a CIDR range (e.g. `192.168.1.0/24`)
- Displays all active IPs in the subnet

---

### 2. **ARP Poisoning**
You will be asked for:
- **Client IP** and **Server IP** (e.g. `192.168.1.10`, `192.168.1.1`)

#### Special Inputs:
- `client IP`, `none` → Poison the first server the client requests
- `none`, `none` → Poison the first client-server pair seen in a ARP broadcast

Then choose:
- **Poisoning Mode**:  
  - `silent`: Send a single ARP packet  
  - `all out`: Continuously poison to increase reliability

After poisoning:
- The tool listens for TCP `SYN` packets and enters **MITM** mode
- You'll be prompted whether to enable **SSL stripping**

---

### 3. **MITM Mode**
Use when ARP poisoning is already done.

You will be asked for:
- **Client IP**
- **Server IP**
- Whether to enable **SSL stripping**

The tool will:
- Wait for a SYN from the client
- Intercept and relay traffic, optionally performing SSL stripping

---

### 4. **Quit**
- Exits the tool

---

## Notes

- All captured packets are logged to a file named `packet_log`.