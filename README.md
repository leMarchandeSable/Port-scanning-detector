# Port-scanning-detector

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
