# CSEC Wireshark Workshop

A hands-on introduction to network protocol analysis using Wireshark. You will sniff plaintext protocols (HTTP, FTP, Telnet, TFTP) and extract credentials and hidden data from live traffic.

## Prerequisites

- **Python 3.8+** - If not installed, see: https://www.python.org/downloads/
- **Wireshark** - If not installed, see: https://www.wireshark.org/download.html
- macOS, Windows, or Linux

**Note for Windows users**: Wireshark must be installed with **Npcap** (not WinPcap). During Npcap installation, check **"Support loopback traffic capture"**. Without this, you will not be able to capture any traffic from the lab.

## Quick Start

The setup script installs all Python dependencies and verifies your environment:

```bash
python3 sniffing_lab.py --setup
```

**What it does:**
- Installs Python packages (`rich`, `pyftpdlib`, `tftpy`)
- Verifies all imports work
- Checks that ports 80, 21, 23, 69 are available
- Checks for root/admin privileges
- (Windows) Checks for Npcap and Telnet client

**After setup passes:**
```bash
# macOS / Linux
sudo python3 sniffing_lab.py

# Windows (run terminal as Administrator)
python3 sniffing_lab.py
```

**Windows Users**: You must run the terminal as Administrator. Right-click your terminal application and select "Run as Administrator", then run the script.

---

## After Setup

1. Run the lab script
2. Open Wireshark
3. Start capturing on the **loopback** interface
4. Press Enter in the lab terminal to begin
5. Type `info` to read the current challenge

```
Commands:
  info              Show the current level's objective
  hint              Get a Wireshark-related hint
  submit <answer>   Submit your answer
  status            Show level progress
  quit              Exit the lab
```

---

## Workshop Structure

The lab runs 4 plaintext protocol servers (HTTP, FTP, Telnet, TFTP) and generates background traffic that simulates real-world scenarios. Your job is to use Wireshark to intercept this traffic and extract hidden information.

There are 5 levels of increasing difficulty. Each level must be completed before the next one unlocks. Only the current level's traffic is active, so you won't see unrelated packets.

| Level | Protocol | Skill Taught |
|-------|----------|-------------|
| 1 | HTTP | Inspecting POST form data |
| 2 | HTTP | Finding and decoding Base64 headers |
| 3 | FTP | Filtering by response codes in noisy traffic |
| 4 | Telnet | Reconstructing a session from a TCP stream |
| 5 | TFTP | Reading individual packet payloads in hex view |

As a bonus exercise, a USB keyboard capture is also included in `keyboard.pcapng`. Some programming experience may be helpful to solve this challenge.

---

## Differences from a Real Network Capture

This workshop runs all traffic on localhost (loopback interface). This differs from capturing on a real network in several ways:

### 1. Loopback vs. Physical Interface
**Real network**: You capture on `eth0`, `en0`, or Wi-Fi and see traffic from other hosts.

**This workshop**: All traffic is on `lo0` (macOS/Linux) or "Adapter for loopback traffic capture" (Windows). Source and destination are both `127.0.0.1`.

**Why**: Loopback is self-contained. No network configuration, no ARP, no need for multiple machines. You focus purely on protocol analysis.

### 2. Plaintext Protocols
**Real network**: Most modern traffic is encrypted (HTTPS, SFTP, SSH). You would see TLS handshakes but not the actual data.

**This workshop**: All protocols are intentionally unencrypted (HTTP, FTP, Telnet, TFTP) so you can read everything in plaintext.

**Why**: The point is to demonstrate exactly why encryption matters. If you can read passwords in Wireshark, so can anyone else on the network.

### 3. Traffic Volume
**Real network**: Thousands of packets per second from many sources, protocols, and conversations.

**This workshop**: Only the current level's traffic is active. You see a small, focused set of packets.

**Why**: Isolating traffic per level lets you learn one filtering technique at a time without being overwhelmed.

---

## Capturing on the Loopback Interface

The loopback interface carries traffic between processes on the same machine. All lab traffic goes through it.

**macOS**:
- In Wireshark, select **Loopback: lo0**

**Linux**:
- In Wireshark, select **Loopback: lo** (or **any**)

**Windows**:
- In Wireshark, select **Adapter for loopback traffic capture** (or **Npcap Loopback Adapter**)
- If you don't see this option, reinstall Npcap with "Support loopback traffic capture" checked

If you see no packets after starting the capture, verify you selected the correct interface. The lab traffic does not go through your Wi-Fi or Ethernet adapter.

---

## Wireshark Quick Reference

### Capture Controls
```
Start capture:      Ctrl+E (or click the shark fin)
Stop capture:       Ctrl+E again
Restart capture:    Ctrl+Shift+R
```

### Display Filters
Display filters let you narrow down what you see in the packet list. Type them in the filter bar at the top.

```
# Filter by protocol
http
ftp
telnet
tftp

# Filter by port
tcp.port == 80
tcp.port == 21
tcp.port == 23
udp.port == 69

# Filter by HTTP method
http.request.method == POST
http.request.method == GET

# Filter by content (searches packet bytes)
http contains "password"
frame contains "secret"

# Filter by response code
http.response.code == 200
http.response.code == 403
ftp.response.code == 230
ftp.response.code == 530

# Combine filters
http.request.method == POST && http.response.code == 200
tcp.port == 21 && ftp.response.code == 230
```

### Following Streams
Right-click any packet and select **Follow > TCP Stream** (or UDP Stream for TFTP). This reconstructs the full conversation between client and server in reading order. Extremely useful for seeing what was sent and received.

### Hex Dump
Click on any packet. The bottom pane shows the raw bytes in hex on the left and ASCII on the right. Click on a field in the middle pane (packet details) to highlight the corresponding bytes below.

---

## Understanding the Protocols

### HTTP (Levels 1 & 2)
HTTP sends everything in plaintext. Form submissions (POST) include the form fields directly in the request body. Headers like `Authorization: Basic ...` encode credentials in Base64, which is encoding, not encryption. Anyone capturing the traffic can decode it instantly.

### FTP (Level 3)
FTP sends credentials as separate `USER` and `PASS` commands in plaintext over a control connection (port 21). The server responds with numeric codes: `230` for successful login, `530` for failed login. File transfers happen on separate data connections.

### Telnet (Level 4)
Telnet sends everything character by character in plaintext, including passwords. The entire session (every keystroke, every line of output) is visible to anyone capturing the traffic. Wireshark's "Follow TCP Stream" reconstructs the session exactly as it appeared on screen.

### TFTP (Level 5)
TFTP is a simple file transfer protocol over UDP (port 69). Files are sent in 512-byte blocks. Each block is a separate DATA packet with a block number. There is no authentication at all.

### USB HID (Bonus)
HID (Human Interface Devices) is a set of protocols for various input devices to communicate over USB. The provided capture is of a USB keyboard. You may find the [HID Usage Tables](https://usb.org/document-library/hid-usage-tables-17) to be a useful resource.

---

## Important: Wireshark Permissions

**macOS**: You may be prompted to install **ChmodBPF** during Wireshark installation. Accept it. If Wireshark shows "no interfaces found", run:
```bash
sudo chmod 644 /dev/bpf*
```
Or reinstall Wireshark and accept the ChmodBPF prompt.

**Linux**: Add your user to the `wireshark` group to capture without root:
```bash
sudo usermod -aG wireshark $USER
# Log out and back in for it to take effect
```

**Windows**: Run Wireshark as Administrator if no interfaces appear.

---

## Troubleshooting

### No packets showing up
- Verify you are capturing on the **loopback** interface, not Wi-Fi/Ethernet
- Make sure the lab script is running and you pressed Enter to start
- Check that `--setup` passed without errors
- (Windows) Verify Npcap is installed with loopback support
- Just wait a bit

### "Address already in use" error
A previous lab instance (or some other software on your device) is still running. Kill it:
```bash
# macOS / Linux
sudo lsof -ti :80 -ti :21 -ti :23 -ti :69 | xargs kill -9

# Windows (Admin terminal)
netstat -ano | findstr ":80 :21 :23 :69"
taskkill /PID <pid> /F
```

### FTP traffic shows as TCP, not FTP
This can happen if Wireshark didn't see the initial FTP banner. Restart the capture (Ctrl+Shift+R) and wait for new FTP connections to appear.

### Telnet not found (Windows)
Enable the Telnet client:
```cmd
dism /online /Enable-Feature /FeatureName:TelnetClient
```
Or use PuTTY in Telnet mode (Host: `localhost`, Port: `23`, Connection type: `Telnet`).

### Level 4: Screen didn't clear / can still scroll up
Some terminal emulators preserve scrollback despite ANSI clear. This doesn't affect the challenge. The point is to practice using Wireshark to reconstruct the telnet session rather than relying on your terminal.

---

## Basic Linux Commands Reference

Essential commands for running the lab:

### Navigation
```bash
# Print current directory
pwd

# List files in current directory
ls

# List with details (size, permissions, dates)
ls -la

# Change directory
cd path/to/directory

# Go to home directory
cd ~
cd $HOME

# Go up one directory
cd ..

# Go to previous directory
cd -
```

### File Operations
```bash
# Create directory
mkdir directory_name

# Remove file
rm filename

# Remove directory and contents
rm -rf directory_name

# Copy file
cp source.txt destination.txt

# Move/rename file
mv oldname.txt newname.txt

# View file contents
cat file.txt

# View file with paging
less file.txt
# (press 'q' to quit)

# Edit file
vim file.txt
nano file.txt
```

### Process Management
```bash
# List running processes
ps aux

# Find specific process
ps aux | grep process_name

# Kill process by PID
kill <PID>

# Kill process by name
pkill process_name

# Stop running command
Ctrl+C
```

### System Information
```bash
# Check disk space
df -h

# Check memory usage
free -h

# Check CPU/memory usage (live)
top
# (press 'q' to quit)

# Download file from URL
wget https://example.com/file.tar.gz

# Extract tar.gz archive
tar -xvzf file.tar.gz
```

### Network Tools
```bash
# Show active connections
netstat -an

# Show listening ports
ss -tulpn        # Linux
lsof -i -P       # macOS

# Test connectivity
ping localhost
curl http://localhost

# Base64 decode (useful for Level 2)
echo 'dXNlcjpwYXNz' | base64 -d
```

---

## Disclaimer

**Educational Purpose**: This workshop demonstrates why plaintext protocols are dangerous. The servers and traffic are intentionally insecure for educational purposes. Do not use these techniques on networks you do not own or have explicit permission to test.

**Your Responsibility**: You are solely responsible for how you use this knowledge. The instructor and workshop organizers take no responsibility for:
- Hardware issues, data loss, or system instability
- Unauthorized network sniffing or interception
- Misuse of techniques learned (capturing credentials on public/corporate networks)
- Any consequences of your actions

Participation in this workshop is entirely voluntary. By choosing to participate, you agree to use this knowledge ethically and legally, and accept full responsibility for your actions.

---

## Additional Resources

### Foundational Resources

- [Wireshark User's Guide](https://www.wireshark.org/docs/wsug_html_chunked/) - Official documentation
- [Wireshark Wiki: Sample Captures](https://wiki.wireshark.org/SampleCaptures) - Real pcaps organized by protocol
- [Wireshark Display Filter Reference](https://www.wireshark.org/docs/dfref/) - Complete filter field reference
- [Practical Packet Analysis Sample Captures](https://github.com/chrissanders/packets) - Beginner-friendly pcaps from Chris Sanders' book

### Practice & Further Learning

- [Network Forensics Puzzle Contest](https://forensicscontest.com/puzzles) - Pcap-based investigation puzzles, closest to this workshop's format
- [CyberDefenders Blue Team Challenges](https://cyberdefenders.org/blueteam-ctf-challenges/) - Gamified PCAP analysis (WebStrike, PacketMaze, Trident)
- [Malware Traffic Analysis](https://www.malware-traffic-analysis.net/) - Real-world malware pcaps with exercises
- [NETRESEC Public PCAP Files](https://www.netresec.com/?page=PcapFiles) - Aggregated pcap sources from CTFs, research, and honeypots

---

Authors: Sasha Zyuzin, Clarence Lam

Good luck!
