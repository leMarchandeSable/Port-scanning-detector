# Port-scanning-detector

Certainly, here's a README file that you can use for your GitHub project. This README is tailored to your packet scan and detection project:

# Packet Scan Detection

Packet Scan Detection is a Python script that analyzes network packet captures (PCAP files) to detect and log two types of network scan activities: stealth scans and TCP scans. It can be a valuable tool for identifying potential security threats in your network traffic.

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Usage](#usage)
- [Getting Started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [How it Works](#how-it-works)

## Overview

Network scans are a common technique used by attackers to probe and discover vulnerabilities in a target network. Packet Scan Detection helps you identify these malicious activities by looking for specific patterns and characteristics in network packets.

## Key Features

- Detects Stealth Scans: Identifies packets that exhibit characteristics of stealth scans, including specific TCP flags, window sizes, and header lengths.
- Detects TCP Scans: Tracks TCP conversations to detect TCP scans, such as SYN/ACK or RST/ACK combinations.
- Logging: Logs detected scan activities in a "log.txt" file, providing information about the attack, including file name, packet number, attacker's IP, target IP, and attacking port.

## Usage

To use Packet Scan Detection, follow these steps:

1. **Clone the Repository**: Clone this GitHub repository to your local machine.

2. **Install Dependencies**: Make sure you have the necessary dependencies, including the Scapy library.

3. **Run the Script**: Run the `scan_detection` function by specifying the path to the PCAP file you want to analyze.

4. **View the Results**: Check the "log.txt" file for logged scan activities and their details.

## Getting Started

### Prerequisites

Before running the script, you need to have the following prerequisites:

- Python 3.7 or higher
- Scapy library

### Installation

1. Clone the repository:

```bash
git clone https://github.com/yourusername/your-repo.git
cd your-repo
```

2. Install the required dependencies, especially the Scapy library:

```bash
pip install scapy
```

## How it Works

The script analyzes network packets within a PCAP file and looks for characteristics specific to stealth scans and TCP scans. When it identifies such activities, it logs the relevant information into a "log.txt" file for further analysis.
We acknowledge that no network or company is completely immune to cyber attacks. While
we cannot completely prevent an attack, we can strengthen our defense by implementing
various security tools. Some of these tools actively block attempts while others passively
detect intrusions. The PSDS belongs to the latter category, it is a passive security tool
designed to detect and log port scanning attempts. Our assumption is that cyber attacks
usually begin with a reconnaissance phase, which often involves port scanning. The primary
goal of our PSDS tool is to accurately record the date, time, and other details of these
attempts, providing a starting point for further analysis of the attack. The PSDS can
significantly reduce the time and resources required for packet analysis by focusing on the
specific time frame of the attack.
Our tool, the PSDS, has three main components: the Network Capturing System, the
Pattern-based Port Scan Detection, and the logging and alerting component.:

![image](https://user-images.githubusercontent.com/95425179/213093619-8ea4c817-66d8-4531-9773-2627c8931be2.png)
