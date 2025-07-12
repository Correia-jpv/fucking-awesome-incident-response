# Awesome Incident Response [![Awesome](https://cdn.rawgit.com/sindresorhus/awesome/d7305f38d29fed78fa85652e3a63e154dd8e8829/media/badge.svg)](https://github.com/sindresorhus/awesome) [![Check URLs](https://github.com/correia-jpv/fucking-awesome-incident-response/actions/workflows/check_urls.yml/badge.svg)](https://github.com/correia-jpv/fucking-awesome-incident-response/actions/workflows/check_urls.yml)

> A curated list of tools and resources for security incident response, aimed to help security analysts and [DFIR](http://www.acronymfinder.com/Digital-Forensics%2c-Incident-Response-%28DFIR%29.html) teams.

Digital Forensics and Incident Response (DFIR) teams are groups of people in an organization responsible for managing the response to a security incident, including gathering evidence of the incident, remediating its effects, and implementing controls to prevent the incident from recurring in the future.

## Contents

- [Adversary Emulation](#adversary-emulation)
- [All-In-One Tools](#all-in-one-tools)
- [Books](#books)
- [Communities](#communities)
- [Disk Image Creation Tools](#disk-image-creation-tools)
- [Evidence Collection](#evidence-collection)
- [Incident Management](#incident-management)
- [Knowledge Bases](#knowledge-bases)
- [Linux Distributions](#linux-distributions)
- [Linux Evidence Collection](#linux-evidence-collection)
- [Log Analysis Tools](#log-analysis-tools)
- [Memory Analysis Tools](#memory-analysis-tools)
- [Memory Imaging Tools](#memory-imaging-tools)
- [OSX Evidence Collection](#osx-evidence-collection)
- [Other Lists](#other-lists)
- [Other Tools](#other-tools)
- [Playbooks](#playbooks)
- [Process Dump Tools](#process-dump-tools)
- [Sandboxing/Reversing Tools](#sandboxingreversing-tools)
- [Scanner Tools](#scanner-tools)
- [Timeline Tools](#timeline-tools)
- [Videos](#videos)
- [Windows Evidence Collection](#windows-evidence-collection)

## IR Tools Collection

### Adversary Emulation

* <b><code>&nbsp;&nbsp;2621⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;444🍴</code></b> [APTSimulator](https://github.com/NextronSystems/APTSimulator)) - Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised.
* <b><code>&nbsp;10748⭐</code></b> <b><code>&nbsp;&nbsp;2940🍴</code></b> [Atomic Red Team (ART)](https://github.com/redcanaryco/atomic-red-team)) - Small and highly portable detection tests mapped to the MITRE ATT&CK Framework.
* <b><code>&nbsp;&nbsp;&nbsp;255⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;64🍴</code></b> [AutoTTP](https://github.com/jymcheong/AutoTTP)) - Automated Tactics Techniques & Procedures. Re-running complex sequences manually for regression tests, product evaluations, generate data for researchers.
* <b><code>&nbsp;&nbsp;6270⭐</code></b> <b><code>&nbsp;&nbsp;1190🍴</code></b> [Caldera](https://github.com/mitre/caldera)) - Automated adversary emulation system that performs post-compromise adversarial behavior within Windows Enterprise networks. It generates plans during operation using a planning system and a pre-configured adversary model based on the Adversarial Tactics, Techniques & Common Knowledge (ATT&CK™) project.
* <b><code>&nbsp;&nbsp;1018⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;147🍴</code></b> [DumpsterFire](https://github.com/TryCatchHCF/DumpsterFire)) - Modular, menu-driven, cross-platform tool for building repeatable, time-delayed, distributed security events. Easily create custom event chains for Blue Team drills and sensor /   alert mapping. Red Teams can create decoy incidents, distractions, and lures to support and scale their operations.
* <b><code>&nbsp;&nbsp;1124⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;154🍴</code></b> [Metta](https://github.com/uber-common/metta)) - Information security preparedness tool to do adversarial simulation.
* <b><code>&nbsp;&nbsp;1316⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;145🍴</code></b> [Network Flight Simulator](https://github.com/alphasoc/flightsim)) - Lightweight utility used to generate malicious network traffic and help security teams to evaluate security controls and network visibility.
* <b><code>&nbsp;&nbsp;1078⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;218🍴</code></b> [Red Team Automation (RTA)](https://github.com/endgameinc/RTA)) - RTA provides a framework of scripts designed to allow blue teams to test their detection capabilities against malicious tradecraft, modeled after MITRE ATT&CK.
* <b><code>&nbsp;&nbsp;1290⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;199🍴</code></b> [RedHunt-OS](https://github.com/redhuntlabs/RedHunt-OS)) - Virtual machine for adversary emulation and threat hunting.

### All-In-One Tools

* 🌎 [Belkasoft Evidence Center](belkasoft.com/ec) -  The toolkit will quickly extract digital evidence from multiple sources by analyzing hard drives, drive images, memory dumps, iOS, Blackberry and Android backups, UFED, JTAG and chip-off dumps.
* <b><code>&nbsp;&nbsp;&nbsp;655⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;145🍴</code></b> [CimSweep](https://github.com/PowerShellMafia/CimSweep)) - Suite of CIM/WMI-based tools that enable the ability to perform incident response and hunting operations remotely across all versions of Windows.
* <b><code>&nbsp;&nbsp;&nbsp;144⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;25🍴</code></b> [CIRTkit](https://github.com/byt3smith/CIRTKit)) - CIRTKit is not just a collection of tools, but also a framework to aid in the ongoing unification of Incident Response and Forensics investigation processes.
* [Cyber Triage](http://www.cybertriage.com) - Cyber Triage collects and analyzes host data to determine if it is compromised. It's scoring system and recommendation engine allow you to quickly focus on the important artifacts. It can import data from its collection tool, disk images, and other collectors (such as KAPE). It can run on an examiner's desktop or in a server model. Developed by Sleuth Kit Labs, which also makes Autopsy. 
* <b><code>&nbsp;&nbsp;1023⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;72🍴</code></b> [Dissect](https://github.com/fox-it/dissect)) - Dissect is a digital forensics & incident response framework and toolset that allows you to quickly access and analyse forensic artefacts from various disk and file formats, developed by Fox-IT (part of NCC Group).
* <b><code>&nbsp;&nbsp;&nbsp;617⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;88🍴</code></b> [Doorman](https://github.com/mwielgoszewski/doorman)) - osquery fleet manager that allows remote management of osquery configurations retrieved by nodes. It takes advantage of osquery's TLS configuration, logger, and distributed read/write endpoints, to give administrators visibility across a fleet of devices with minimal overhead and intrusiveness.
* <b><code>&nbsp;&nbsp;&nbsp;187⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;54🍴</code></b> [Falcon Orchestrator](https://github.com/CrowdStrike/falcon-orchestrator)) - Extendable Windows-based application that provides workflow automation, case management and security response functionality.
* <b><code>&nbsp;&nbsp;7465⭐</code></b> <b><code>&nbsp;&nbsp;1003🍴</code></b> [Flare](https://github.com/fireeye/flare-vm)) - A fully customizable, Windows-based security distribution for malware analysis, incident response, penetration testing.
* <b><code>&nbsp;&nbsp;5226⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;614🍴</code></b> [Fleetdm](https://github.com/fleetdm/fleet)) - State of the art host monitoring platform tailored for security experts. Leveraging Facebook's battle-tested osquery project, Fleetdm delivers continuous updates, features and fast answers to big questions.
* <b><code>&nbsp;&nbsp;4928⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;791🍴</code></b> [GRR Rapid Response](https://github.com/google/grr)) - Incident response framework focused on remote live forensics. It consists of a python agent (client) that is installed on target systems, and a python server infrastructure that can manage and talk to the agent. Besides the included Python API client, <b><code>&nbsp;&nbsp;&nbsp;&nbsp;56⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [PowerGRR](https://github.com/swisscom/PowerGRR)) provides an API client library in PowerShell working on Windows, Linux and macOS for GRR automation and scripting.
* <b><code>&nbsp;&nbsp;1214⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;235🍴</code></b> [IRIS](https://github.com/dfir-iris/iris-web)) - IRIS is a web collaborative platform for incident response analysts allowing to share investigations at a technical level.
* <b><code>&nbsp;&nbsp;&nbsp;831⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;116🍴</code></b> [Kuiper](https://github.com/DFIRKuiper/Kuiper)) - Digital Forensics Investigation Platform
* 🌎 [Limacharlie](www.limacharlie.io/) - Endpoint security platform composed of a collection of small projects all working together that gives you a cross-platform (Windows, OSX, Linux, Android and iOS) low-level environment for managing and pushing additional modules into memory to extend its functionality.
* <b><code>&nbsp;&nbsp;1583⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;113🍴</code></b> [Matano](https://github.com/matanolabs/matano)): Open source serverless security lake platform on AWS that lets you ingest, store, and analyze petabytes of security data into an Apache Iceberg data lake and run realtime Python detections as code.
* <b><code>&nbsp;&nbsp;2170⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;328🍴</code></b> [MozDef](https://github.com/mozilla/MozDef)) - Automates the security incident handling process and facilitate the real-time activities of incident handlers.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;46⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6🍴</code></b> [MutableSecurity](https://github.com/MutableSecurity/mutablesecurity)) - CLI program for automating the setup, configuration, and use of cybersecurity solutions.
* <b><code>&nbsp;&nbsp;&nbsp;603⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;125🍴</code></b> [nightHawk](https://github.com/biggiesmallsAG/nightHawkResponse)) - Application built for asynchronous forensic data presentation using ElasticSearch as the backend. It's designed to ingest Redline collections.
* [Open Computer Forensics Architecture](http://sourceforge.net/projects/ocfa/) - Another popular distributed open-source computer forensics framework. This framework was built on Linux platform and uses postgreSQL database for storing data.
* 🌎 [osquery](osquery.io/) - Easily ask questions about your Linux and macOS infrastructure using a SQL-like query language; the provided *incident-response pack* helps you detect and respond to breaches.
* 🌎 [Redline](www.fireeye.com/services/freeware/redline.html) - Provides host investigative capabilities to users to find signs of malicious activity through memory and file analysis, and the development of a threat assessment profile.
* <b><code>&nbsp;&nbsp;&nbsp;397⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;55🍴</code></b> [SOC Multi-tool](https://github.com/zdhenard42/SOC-Multitool)) - A powerful and user-friendly browser extension that streamlines investigations for security professionals.
* [The Sleuth Kit & Autopsy](http://www.sleuthkit.org) - Unix and Windows based tool which helps in forensic analysis of computers. It comes with various tools which helps in digital forensics. These tools help in analyzing disk images, performing in-depth analysis of file systems, and various other things.
* 🌎 [TheHive](thehive-project.org/) - Scalable 3-in-1 open source and free solution designed to make life easier for SOCs, CSIRTs, CERTs and any information security practitioner dealing with security incidents that need to be investigated and acted upon swiftly.
* <b><code>&nbsp;&nbsp;3351⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;537🍴</code></b> [Velociraptor](https://github.com/Velocidex/velociraptor)) - Endpoint visibility and collection tool
* [X-Ways Forensics](http://www.x-ways.net/forensics/) - Forensics tool for Disk cloning and imaging. It can be used to find deleted files and disk analysis.
* <b><code>&nbsp;&nbsp;&nbsp;797⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;81🍴</code></b> [Zentral](https://github.com/zentralopensource/zentral)) - Combines osquery's powerful endpoint inventory features with a flexible notification and action framework. This enables one to identify and react to changes on OS X and Linux clients.

### Books

* 🌎 [Applied Incident Response](www.amazon.com/Applied-Incident-Response-Steve-Anson/dp/1119560268/) - Steve Anson's book on Incident Response.
* 🌎 [Art of Memory Forensics](www.amazon.com/Art-Memory-Forensics-Detecting-Malware/dp/1118825098/) - Detecting Malware and Threats in Windows, Linux, and Mac Memory.
* 🌎 [Crafting the InfoSec Playbook: Security Monitoring and Incident Response Master Plan](www.amazon.com/Crafting-InfoSec-Playbook-Security-Monitoring/dp/1491949406) - by Jeff Bollinger, Brandon Enright and Matthew Valites.
* 🌎 [Digital Forensics and Incident Response: Incident response techniques and procedures to respond to modern cyber threats](www.amazon.com/Digital-Forensics-Incident-Response-techniques/dp/183864900X) - by Gerard Johansen.
* 🌎 [Introduction to DFIR](medium.com/@sroberts/introduction-to-dfir-d35d5de4c180/) - By Scott J. Roberts.
* 🌎 [Incident Response & Computer Forensics, Third Edition](www.amazon.com/Incident-Response-Computer-Forensics-Third/dp/0071798684/) - The definitive guide to incident response.
* 🌎 [Incident Response Techniques for Ransomware Attacks](www.amazon.com/Incident-Response-Techniques-Ransomware-Attacks/dp/180324044X) - A great guide to build an incident response strategy for ransomware attacks. By Oleg Skulkin.
* 🌎 [Incident Response with Threat Intelligence](www.amazon.com/Incident-response-Threat-Intelligence-intelligence-based/dp/1801072957) - Great reference to build an incident response plan based also on Threat Intelligence. By Roberto Martinez.
* 🌎 [Intelligence-Driven Incident Response](www.amazon.com/Intelligence-Driven-Incident-Response-Outwitting-Adversary-ebook-dp-B074ZRN5T7/dp/B074ZRN5T7) - By Scott J. Roberts, Rebekah Brown.
* 🌎 [Operator Handbook: Red Team + OSINT + Blue Team Reference](www.amazon.com/Operator-Handbook-Team-OSINT-Reference/dp/B085RR67H5/) - Great reference for incident responders.
* 🌎 [Practical Memory Forensics](www.amazon.com/Practical-Memory-Forensics-Jumpstart-effective/dp/1801070334) - The definitive guide to practice memory forensics. By Svetlana Ostrovskaya and Oleg Skulkin.
* [The Practice of Network Security Monitoring: Understanding Incident Detection and Response](http://www.amazon.com/gp/product/1593275099) - Richard Bejtlich's book on IR.

### Communities

* 🌎 [Digital Forensics Discord Server](discordapp.com/invite/JUqe9Ek) - Community of 8,000+ working professionals from Law Enforcement, Private Sector, and Forensic Vendors. Additionally, plenty of students and hobbyists! Guide 🌎 [here](aboutdfir.com/a-beginners-guide-to-the-digital-forensics-discord-server/).
* 🌎 [Slack DFIR channel](dfircommunity.slack.com) - Slack DFIR Communitiy channel - 🌎 [Signup here](start.paloaltonetworks.com/join-our-slack-community).

### Disk Image Creation Tools

* [AccessData FTK Imager](http://accessdata.com/product-download/?/support/adownloads#FTKImager) - Forensics tool whose main purpose is to preview recoverable data from a disk of any kind. FTK Imager can also acquire live memory and paging file on 32bit and 64bit systems.
* <b><code>&nbsp;&nbsp;&nbsp;467⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;109🍴</code></b> [Bitscout](https://github.com/vitaly-kamluk/bitscout)) - Bitscout by Vitaly Kamluk helps you build your fully-trusted customizable LiveCD/LiveUSB image to be used for remote digital forensics (or perhaps any other task of your choice). It is meant to be transparent and monitorable by the owner of the system, forensically sound, customizable and compact.
* [GetData Forensic Imager](http://www.forensicimager.com/) - Windows based program that will acquire, convert, or verify a forensic image in one of the following common forensic file formats.
* [Guymager](http://guymager.sourceforge.net) - Free forensic imager for media acquisition on Linux.
* 🌎 [Magnet ACQUIRE](www.magnetforensics.com/magnet-acquire/) - ACQUIRE by Magnet Forensics allows various types of disk acquisitions to be performed on Windows, Linux, and OS X as well as mobile operating systems.

### Evidence Collection

* <b><code>&nbsp;&nbsp;&nbsp;104⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;33🍴</code></b> [Acquire](https://github.com/fox-it/acquire)) - Acquire is a tool to quickly gather forensic artifacts from disk images or a live system into a lightweight container. This makes Acquire an excellent tool to, among others, speedup the process of digital forensic triage. It uses <b><code>&nbsp;&nbsp;1023⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;72🍴</code></b> [Dissect](https://github.com/fox-it/dissect)) to gather that information from the raw disk, if possible.
* <b><code>&nbsp;&nbsp;&nbsp;290⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;23🍴</code></b> [artifactcollector](https://github.com/forensicanalysis/artifactcollector)) - The artifactcollector project provides a software that collects forensic artifacts on systems.
* <b><code>&nbsp;&nbsp;1226⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;206🍴</code></b> [bulk_extractor](https://github.com/simsong/bulk_extractor)) - Computer forensics tool that scans a disk image, a file, or a directory of files and extracts useful information without parsing the file system or file system structures. Because of ignoring the file system structure, the program distinguishes itself in terms of speed and thoroughness.
* <b><code>&nbsp;&nbsp;&nbsp;339⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;50🍴</code></b> [Cold Disk Quick Response](https://github.com/rough007/CDQR)) - Streamlined list of parsers to quickly analyze a forensic image file (`dd`, E01, `.vmdk`, etc) and output nine reports.
* <b><code>&nbsp;&nbsp;&nbsp;685⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;94🍴</code></b> [CyLR](https://github.com/orlikoski/CyLR)) - The CyLR tool collects forensic artifacts from hosts with NTFS file systems quickly, securely and minimizes impact to the host.
* <b><code>&nbsp;&nbsp;1138⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;214🍴</code></b> [Forensic Artifacts](https://github.com/ForensicArtifacts/artifacts)) - Digital Forensics Artifact Repository
* <b><code>&nbsp;&nbsp;&nbsp;483⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;94🍴</code></b> [ir-rescue](https://github.com/diogo-fernan/ir-rescue)) - Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.
* 🌎 [Live Response Collection](www.brimorlabs.com/tools/) - Automated tool that collects volatile data from Windows, OSX, and \*nix based operating systems.
* <b><code>&nbsp;&nbsp;&nbsp;247⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;48🍴</code></b> [Margarita Shotgun](https://github.com/ThreatResponse/margaritashotgun)) - Command line utility (that works with or without Amazon EC2 instances) to parallelize remote memory acquisition.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;41⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [SPECTR3](https://github.com/alpine-sec/SPECTR3)) - Acquire, triage and investigate remote evidence via portable iSCSI readonly access
* <b><code>&nbsp;&nbsp;1015⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;156🍴</code></b> [UAC](https://github.com/tclahr/uac)) - UAC (Unix-like Artifacts Collector) is a Live Response collection script for Incident Response that makes use of native binaries and tools to automate the collection of AIX, Android, ESXi, FreeBSD, Linux, macOS, NetBSD, NetScaler, OpenBSD and Solaris systems artifacts.

### Incident Management

* <b><code>&nbsp;&nbsp;&nbsp;408⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;37🍴</code></b> [Catalyst](https://github.com/SecurityBrewery/catalyst)) - A free SOAR system that helps to automate alert handling and incident response processes.
* 🌎 [CyberCPR](www.cybercpr.com) - Community and commercial incident management tool with Need-to-Know built in to support GDPR compliance while handling sensitive incidents.
* 🌎 [Cyphon](medevel.com/cyphon/) - Cyphon eliminates the headaches of incident management by streamlining a multitude of related tasks through a single platform. It receives, processes and triages events to provide an all-encompassing solution for your analytic workflow — aggregating data, bundling and prioritizing alerts, and empowering analysts to investigate and document incidents.
* 🌎 [CORTEX XSOAR](www.paloaltonetworks.com/cortex/xsoar) - Paloalto security orchestration, automation and response platform with full Incident lifecycle management and many integrations to enhance automations.
* <b><code>&nbsp;&nbsp;&nbsp;325⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;73🍴</code></b> [DFTimewolf](https://github.com/log2timeline/dftimewolf)) - A framework for orchestrating forensic collection, processing and data export.
* <b><code>&nbsp;&nbsp;&nbsp;522⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;86🍴</code></b> [DFIRTrack](https://github.com/dfirtrack/dfirtrack)) - Incident Response tracking application handling one or more incidents via cases and tasks with a lot of affected systems and artifacts.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Fast Incident Response (FIR)](https://github.com/certsocietegenerale/FIR/)) - Cybersecurity incident management platform designed with agility and speed in mind. It allows for easy creation, tracking, and reporting of cybersecurity incidents and is useful for CSIRTs, CERTs and SOCs alike.
* 🌎 [RTIR](www.bestpractical.com/rtir/) - Request Tracker for Incident Response (RTIR) is the premier open source incident handling system targeted for computer security teams. We worked with over a dozen CERT and CSIRT teams around the world to help you handle the ever-increasing volume of incident reports. RTIR builds on all the features of Request Tracker.
* <b><code>&nbsp;&nbsp;&nbsp;248⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;48🍴</code></b> [Sandia Cyber Omni Tracker (SCOT)](https://github.com/sandialabs/scot)) - Incident Response collaboration and knowledge capture tool focused on flexibility and ease of use. Our goal is to add value to the incident response process without burdening the user.
* <b><code>&nbsp;&nbsp;1984⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;365🍴</code></b> [Shuffle](https://github.com/frikky/Shuffle)) - A general purpose security automation platform focused on accessibility.
* <b><code>&nbsp;&nbsp;&nbsp;432⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;91🍴</code></b> [threat_note](https://github.com/defpoint/threat_note)) - Lightweight investigation notebook that allows security researchers the ability to register and retrieve indicators related to their research.
* 🌎 [Zenduty](www.zenduty.com) - Zenduty is a novel incident management platform providing end-to-end incident alerting, on-call management and response orchestration, giving teams greater control and automation over the incident management lifecycle.

### Knowledge Bases

* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;83⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;17🍴</code></b> [Digital Forensics Artifact Knowledge Base](https://github.com/ForensicArtifacts/artifacts-kb)) - Digital Forensics Artifact Knowledge Base
* <b><code>&nbsp;&nbsp;2388⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;414🍴</code></b> [Windows Events Attack Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)) - Windows Events Attack Samples
* <b><code>&nbsp;&nbsp;&nbsp;176⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;21🍴</code></b> [Windows Registry Knowledge Base](https://github.com/libyal/winreg-kb)) - Windows Registry Knowledge Base

### Linux Distributions

* 🌎 [The Appliance for Digital Investigation and Analysis (ADIA)](forensics.cert.org/#ADIA) - VMware-based appliance used for digital investigation and acquisition and is built entirely from public domain software. Among the tools contained in ADIA are Autopsy, the Sleuth Kit, the Digital Forensics Framework, log2timeline, Xplico, and Wireshark. Most of the system maintenance uses Webmin. It is designed for small-to-medium sized digital investigations and acquisitions. The appliance runs under Linux, Windows, and Mac OS. Both i386 (32-bit) and x86_64 (64-bit) versions are available.
* [Computer Aided Investigative Environment (CAINE)](http://www.caine-live.net/index.html) - Contains numerous tools that help investigators during their analysis, including forensic evidence collection.
* <b><code>&nbsp;&nbsp;&nbsp;499⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;71🍴</code></b> [CCF-VM](https://github.com/rough007/CCF-VM)) - CyLR CDQR Forensics Virtual Machine (CCF-VM): An all-in-one solution to parsing collected data, making it easily searchable with built-in common searches, enable searching of single and multiple hosts simultaneously.
* 🌎 [NST - Network Security Toolkit](sourceforge.net/projects/nst/files/latest/download?source=files) - Linux distribution that includes a vast collection of best-of-breed open source network security applications useful to the network security professional.
* 🌎 [PALADIN](sumuri.com/software/paladin/) - Modified Linux distribution to perform various forensics task in a forensically sound manner. It comes with many open source forensics tools included.
* <b><code>&nbsp;&nbsp;3091⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;524🍴</code></b> [Security Onion](https://github.com/Security-Onion-Solutions/security-onion)) - Special Linux distro aimed at network security monitoring featuring advanced analysis tools.
* [SANS Investigative Forensic Toolkit (SIFT) Workstation](http://digital-forensics.sans.org/community/downloads) - Demonstrates that advanced incident response capabilities and deep dive digital forensic techniques to intrusions can be accomplished using cutting-edge open-source tools that are freely available and frequently updated.

### Linux Evidence Collection

* <b><code>&nbsp;&nbsp;&nbsp;174⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;44🍴</code></b> [FastIR Collector Linux](https://github.com/SekoiaLab/Fastir_Collector_Linux)) - FastIR for Linux collects different artifacts on live Linux and records the results in CSV files.
* <b><code>&nbsp;&nbsp;&nbsp;199⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;19🍴</code></b> [MAGNET DumpIt](https://github.com/MagnetForensics/dumpit-linux)) - Fast memory acquisition open source tool for Linux written in Rust. Generate full memory crash dumps of Linux machines.

### Log Analysis Tools

* <b><code>&nbsp;&nbsp;&nbsp;205⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;25🍴</code></b> [AppCompatProcessor](https://github.com/mbevilacqua/appcompatprocessor)) - AppCompatProcessor has been designed to extract additional value from enterprise-wide AppCompat / AmCache data beyond the classic stacking and grepping techniques.
* <b><code>&nbsp;&nbsp;1353⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;244🍴</code></b> [APT Hunter](https://github.com/ahmedkhlief/APT-Hunter)) - APT-Hunter is Threat Hunting tool for windows event logs.
* <b><code>&nbsp;&nbsp;3201⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;288🍴</code></b> [Chainsaw](https://github.com/countercept/chainsaw)) - Chainsaw provides a powerful ‘first-response’ capability to quickly identify threats within Windows event logs.
* 🌎 [Event Log Explorer](eventlogxp.com/) - Tool developed to quickly analyze log files and other data.
* 🌎 [Event Log Observer](lizard-labs.com/event_log_observer.aspx) - View, analyze and monitor events recorded in Microsoft Windows event logs with this GUI tool.
* <b><code>&nbsp;&nbsp;2714⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;231🍴</code></b> [Hayabusa](https://github.com/Yamato-Security/hayabusa)) - Hayabusa is a Windows event log fast forensics timeline generator and threat hunting tool created by the Yamato Security group in Japan.
* 🌎 [Kaspersky CyberTrace](support.kaspersky.com/13850) - Threat intelligence fusion and analysis tool that integrates threat data feeds with SIEM solutions. Users can immediately leverage threat intelligence for security monitoring and incident report (IR) activities in the workflow of their existing security operations.
* 🌎 [Log Parser Lizard](lizard-labs.com/log_parser_lizard.aspx) - Execute SQL queries against structured log data: server logs, Windows Events, file system, Active Directory, log4net logs, comma/tab separated text, XML or JSON files. Also provides a GUI to Microsoft LogParser 2.2 with powerful UI elements: syntax editor, data grid, chart, pivot table, dashboard, query manager and more.
* <b><code>&nbsp;&nbsp;&nbsp;213⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;50🍴</code></b> [Lorg](https://github.com/jensvoid/lorg)) - Tool for advanced HTTPD logfile security analysis and forensics.
* <b><code>&nbsp;&nbsp;&nbsp;154⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;23🍴</code></b> [Logdissect](https://github.com/dogoncouch/logdissect)) - CLI utility and Python API for analyzing log files and other data.
* <b><code>&nbsp;&nbsp;2919⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;462🍴</code></b> [LogonTracer](https://github.com/JPCERTCC/LogonTracer)) - Tool to investigate malicious Windows logon by visualizing and analyzing Windows event log.
* <b><code>&nbsp;&nbsp;9396⭐</code></b> <b><code>&nbsp;&nbsp;2366🍴</code></b> [Sigma](https://github.com/SigmaHQ/sigma)) - Generic signature format for SIEM systems already containing an extensive ruleset.
* <b><code>&nbsp;&nbsp;2873⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;330🍴</code></b> [StreamAlert](https://github.com/airbnb/streamalert)) - Serverless, real-time log data analysis framework, capable of ingesting custom data sources and triggering alerts using user-defined logic.
* <b><code>&nbsp;&nbsp;&nbsp;422⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;57🍴</code></b> [SysmonSearch](https://github.com/JPCERTCC/SysmonSearch)) - SysmonSearch makes Windows event log analysis more effective and less time consuming by aggregation of event logs.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;31⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;2🍴</code></b> [WELA](https://github.com/Yamato-Security/WELA)) - Windows Event Log Analyzer aims to be the Swiss Army knife for Windows event logs.
* <b><code>&nbsp;&nbsp;&nbsp;722⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;99🍴</code></b> [Zircolite](https://github.com/wagga40/Zircolite)) - A standalone and fast SIGMA-based detection tool for EVTX or JSON.

### Memory Analysis Tools

* <b><code>&nbsp;&nbsp;&nbsp;962⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;81🍴</code></b> [AVML](https://github.com/microsoft/avml)) - A portable volatile memory acquisition tool for Linux.
* <b><code>&nbsp;&nbsp;&nbsp;259⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;37🍴</code></b> [Evolve](https://github.com/JamesHabben/evolve)) - Web interface for the Volatility Memory Forensics Framework.
* <b><code>&nbsp;&nbsp;&nbsp;286⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;51🍴</code></b> [inVtero.net](https://github.com/ShaneK2/inVtero.net)) - Advanced memory analysis for Windows x64 with nested hypervisor support.
* <b><code>&nbsp;&nbsp;1833⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;344🍴</code></b> [LiME](https://github.com/504ensicsLabs/LiME)) - Loadable Kernel Module (LKM), which allows the acquisition of volatile memory from Linux and Linux-based devices, formerly called DMD.
* <b><code>&nbsp;&nbsp;&nbsp;489⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;69🍴</code></b> [MalConfScan](https://github.com/JPCERTCC/MalConfScan)) - MalConfScan is a Volatility plugin extracts configuration data of known malware. Volatility is an open-source memory forensics framework for incident response and malware analysis. This tool searches for malware in memory images and dumps configuration data. In addition, this tool has a function to list strings to which malicious code refers.
* 🌎 [Memoryze](www.fireeye.com/services/freeware/memoryze.html) - Free memory forensic software that helps incident responders find evil in live memory. Memoryze can acquire and/or analyze memory images, and on live systems, can include the paging file in its analysis.
* 🌎 [Memoryze for Mac](www.fireeye.com/services/freeware/memoryze.html) - Memoryze for Mac is Memoryze but then for Macs. A lower number of features, however.
* [MemProcFS] (https://github.com/ufrisk/MemProcFS) - MemProcFS is an easy and convenient way of viewing physical memory as files in a virtual file system.
* <b><code>&nbsp;&nbsp;&nbsp;246⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;22🍴</code></b> [Orochi](https://github.com/LDO-CERT/orochi)) - Orochi is an open source framework for collaborative forensic memory dump analysis.
* [Rekall](http://www.rekall-forensic.com/) - Open source tool (and library) for the extraction of digital artifacts from volatile memory (RAM) samples.
* <b><code>&nbsp;&nbsp;7743⭐</code></b> <b><code>&nbsp;&nbsp;1325🍴</code></b> [Volatility](https://github.com/volatilityfoundation/volatility)) - Advanced memory forensics framework.
* <b><code>&nbsp;&nbsp;3250⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;530🍴</code></b> [Volatility 3](https://github.com/volatilityfoundation/volatility3)) - The volatile memory extraction framework (successor of Volatility)
* <b><code>&nbsp;&nbsp;&nbsp;267⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;50🍴</code></b> [VolatilityBot](https://github.com/mkorman90/VolatilityBot)) - Automation tool for researchers cuts all the guesswork and manual tasks out of the binary extraction phase, or to help the investigator in the first steps of performing a memory analysis investigation.
* <b><code>&nbsp;&nbsp;&nbsp;194⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;50🍴</code></b> [VolDiff](https://github.com/aim4r/VolDiff)) - Malware Memory Footprint Analysis based on Volatility.
* [WindowsSCOPE](http://www.windowsscope.com/windowsscope-cyber-forensics/) - Memory forensics and reverse engineering tool used for analyzing volatile memory offering the capability of analyzing the Windows kernel, drivers, DLLs, and virtual and physical memory.

### Memory Imaging Tools

* [Belkasoft Live RAM Capturer](http://belkasoft.com/ram-capturer) - Tiny free forensic tool to reliably extract the entire content of the computer’s volatile memory – even if protected by an active anti-debugging or anti-dumping system.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Linux Memory Grabber](https://github.com/halpomeranz/lmg/)) - Script for dumping Linux memory and creating Volatility profiles.
* 🌎 [MAGNET DumpIt](www.magnetforensics.com/resources/magnet-dumpit-for-windows) - Fast memory acquisition tool for Windows (x86, x64, ARM64). Generate full memory crash dumps of Windows machines.
* 🌎 [Magnet RAM Capture](www.magnetforensics.com/free-tool-magnet-ram-capture/) - Free imaging tool designed to capture the physical memory of a suspect’s computer. Supports recent versions of Windows.
* [OSForensics](http://www.osforensics.com/) - Tool to acquire live memory on 32-bit and 64-bit systems. A dump of an individual process’s memory space or physical memory dump can be done.

### OSX Evidence Collection

* 🌎 [Knockknock](objective-see.com/products/knockknock.html) - Displays persistent items(scripts, commands, binaries, etc.) that are set to execute automatically on OSX.
* <b><code>&nbsp;&nbsp;&nbsp;875⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;107🍴</code></b> [macOS Artifact Parsing Tool (mac_apt)](https://github.com/ydkhatri/mac_apt)) - Plugin based forensics framework for quick mac triage that works on live machines, disk images or individual artifact files.
* <b><code>&nbsp;&nbsp;3131⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;277🍴</code></b> [OSX Auditor](https://github.com/jipegit/OSXAuditor)) - Free Mac OS X computer forensics tool.
* <b><code>&nbsp;&nbsp;1887⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;243🍴</code></b> [OSX Collector](https://github.com/yelp/osxcollector)) - OSX Auditor offshoot for live response.
* 🌎 [The ESF Playground](themittenmac.com/the-esf-playground/) - A tool to view the events in Apple Endpoint Security Framework (ESF) in real time.

### Other Lists

* <b><code>&nbsp;&nbsp;&nbsp;620⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;87🍴</code></b> [Awesome Event IDs](https://github.com/stuhli/awesome-event-ids)) - Collection of Event ID resources useful for Digital Forensics and Incident Response.
* <b><code>&nbsp;&nbsp;4452⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;669🍴</code></b> [Awesome Forensics](https://github.com/cugu/awesome-forensics)) - A curated list of awesome forensic analysis tools and resources.
* <b><code>&nbsp;&nbsp;2263⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;567🍴</code></b> [Didier Stevens Suite](https://github.com/DidierStevens/DidierStevensSuite)) - Tool collection
* 🌎 [Eric Zimmerman Tools](ericzimmerman.github.io/) - An updated list of forensic tools created by Eric Zimmerman, an instructor for SANS institute.
* <b><code>&nbsp;&nbsp;&nbsp;930⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;137🍴</code></b> [List of various Security APIs](https://github.com/deralexxx/security-apis)) - Collective list of public JSON APIs for use in security.

### Other Tools

* 🌎 [Cortex](thehive-project.org) - Cortex allows you to analyze observables such as IP and email addresses, URLs, domain names, files or hashes one by one or in bulk mode using a Web interface. Analysts can also automate these operations using its REST API.
* 🌎 [Crits](crits.github.io/) - Web-based tool which combines an analytic engine with a cyber threat database.
* <b><code>&nbsp;&nbsp;&nbsp;633⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;59🍴</code></b> [Diffy](https://github.com/Netflix-Skunkworks/diffy)) - DFIR tool developed by Netflix's SIRT that allows an investigator to quickly scope a compromise across cloud instances (Linux instances on AWS, currently) during an incident and efficiently triaging those instances for followup actions by showing differences against a baseline.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;25⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;3🍴</code></b> [domfind](https://github.com/diogo-fernan/domfind)) - Python DNS crawler for finding identical domain names under different TLDs.
* <b><code>&nbsp;&nbsp;&nbsp;122⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;23🍴</code></b> [Fileintel](https://github.com/keithjjones/fileintel)) - Pull intelligence per file hash.
* <b><code>&nbsp;&nbsp;3864⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;700🍴</code></b> [HELK](https://github.com/Cyb3rWard0g/HELK)) - Threat Hunting platform.
* <b><code>&nbsp;&nbsp;1206⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;157🍴</code></b> [Hindsight](https://github.com/obsidianforensics/hindsight)) - Internet history forensics for Google Chrome/Chromium.
* <b><code>&nbsp;&nbsp;&nbsp;267⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;51🍴</code></b> [Hostintel](https://github.com/keithjjones/hostintel)) - Pull intelligence per host.
* <b><code>&nbsp;&nbsp;&nbsp;124⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;36🍴</code></b> [imagemounter](https://github.com/ralphje/imagemounter)) - Command line utility and Python package to ease the (un)mounting of forensic disk images.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [Kansa](https://github.com/davehull/Kansa/)) - Modular incident response framework in PowerShell.
* <b><code>&nbsp;&nbsp;&nbsp;306⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;34🍴</code></b> [MFT Browser](https://github.com/kacos2000/MFT_Browser)) - MFT directory tree reconstruction & record info.
* <b><code>&nbsp;&nbsp;&nbsp;831⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;148🍴</code></b> [Munin](https://github.com/Neo23x0/munin)) - Online hash checker for VirusTotal and other services.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;38⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;6🍴</code></b> [PowerSponse](https://github.com/swisscom/PowerSponse)) - PowerSponse is a PowerShell module focused on targeted containment and remediation during security incident response.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;26⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;4🍴</code></b> [PyaraScanner](https://github.com/nogoodconfig/pyarascanner)) - Very simple multi-threaded many-rules to many-files YARA scanning Python script for malware zoos and IR.
* <b><code>&nbsp;&nbsp;&nbsp;241⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;53🍴</code></b> [rastrea2r](https://github.com/rastrea2r/rastrea2r)) - Allows one to scan disks and memory for IOCs using YARA on Windows, Linux and OS X.
* 🌎 [RaQet](raqet.github.io/) - Unconventional remote acquisition and triaging tool that allows triage a disk of a remote computer (client) that is restarted with a purposely built forensic operating system.
* <b><code>&nbsp;&nbsp;&nbsp;965⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;125🍴</code></b> [Raccine](https://github.com/Neo23x0/Raccine)) - A Simple Ransomware Protection
* 🌎 [Stalk](www.percona.com/doc/percona-toolkit/2.2/pt-stalk.html) - Collect forensic data about MySQL when problems occur.
* 🌎 [Scout2](nccgroup.github.io/Scout2/) - Security tool that lets Amazon Web Services administrators assess their environment's security posture.
* <b><code>&nbsp;&nbsp;1800⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;235🍴</code></b> [Stenographer](https://github.com/google/stenographer)) - Packet capture solution which aims to quickly spool all packets to disk, then provide simple, fast access to subsets of those packets. It stores as much history as it possible, managing disk usage, and deleting when disk limits are hit. It's ideal for capturing the traffic just before and during an incident, without the need explicit need to store all of the network traffic.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [sqhunter](https://github.com/0x4d31/sqhunter)) - Threat hunter based on osquery and Salt Open (SaltStack) that can issue ad-hoc or distributed queries without the need for osquery's tls plugin. sqhunter allows you to query open network sockets and check them against threat intelligence sources.
* <b><code>&nbsp;&nbsp;5085⭐</code></b> <b><code>&nbsp;&nbsp;1770🍴</code></b> [sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)) - Sysmon configuration file template with default high-quality event tracing
* <b><code>&nbsp;&nbsp;2821⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;625🍴</code></b> [sysmon-modular](https://github.com/olafhartong/sysmon-modular)) - A repository of sysmon configuration modules
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;38⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;8🍴</code></b> [traceroute-circl](https://github.com/CIRCL/traceroute-circl)) - Extended traceroute to support the activities of CSIRT (or CERT) operators. Usually CSIRT team have to handle incidents based on IP addresses received. Created by Computer Emergency Response Center Luxembourg.
* 🌎 [X-Ray 2.0](www.raymond.cc/blog/xray/) - Windows utility (poorly maintained or no longer maintained) to submit virus samples to AV vendors.

### Playbooks

* <b><code>&nbsp;&nbsp;1001⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;205🍴</code></b> [AWS Incident Response Runbook Samples](https://github.com/aws-samples/aws-incident-response-runbooks/tree/0d9a1c0f7ad68fb2c1b2d86be8914f2069492e21)) - AWS IR Runbook Samples meant to be customized per each entity using them. The three samples are: "DoS or DDoS attack", "credential leakage", and "unintended access to an Amazon S3 bucket".
* <b><code>&nbsp;&nbsp;&nbsp;719⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;241🍴</code></b> [Counteractive Playbooks](https://github.com/counteractive/incident-response-plan-template/tree/master/playbooks)) - Counteractive PLaybooks collection.
* <b><code>&nbsp;&nbsp;&nbsp;382⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;72🍴</code></b> [GuardSIght Playbook Battle Cards](https://github.com/guardsight/gsvsoc_cirt-playbook-battle-cards)) - A collection of Cyber Incident Response Playbook Battle Cards
* <b><code>&nbsp;&nbsp;1063⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;175🍴</code></b> [IRM](https://github.com/certsocietegenerale/IRM)) - Incident Response Methodologies by CERT Societe Generale.
* 🌎 [PagerDuty Incident Response Documentation](response.pagerduty.com/) - Documents that describe parts of the PagerDuty Incident Response process. It provides information not only on preparing for an incident, but also what to do during and after. Source is available on <b><code>&nbsp;&nbsp;1028⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;226🍴</code></b> [GitHub](https://github.com/PagerDuty/incident-response-docs)).
* <b><code>&nbsp;&nbsp;&nbsp;504⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;208🍴</code></b> [Phantom Community Playbooks](https://github.com/phantomcyber/playbooks)) - Phantom Community Playbooks for Splunk but also customizable for other use.
* <b><code>&nbsp;&nbsp;4258⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;832🍴</code></b> [ThreatHunter-Playbook](https://github.com/OTRF/ThreatHunter-Playbook)) - Playbook to aid the development of techniques and hypothesis for hunting campaigns.

### Process Dump Tools

* 🌎 [Microsoft ProcDump](docs.microsoft.com/en-us/sysinternals/downloads/procdump) - Dumps any running Win32 processes memory image on the fly.
* [PMDump](http://www.ntsecurity.nu/toolbox/pmdump/) - Tool that lets you dump the memory contents of a process to a file without stopping the process.

### Sandboxing/Reversing Tools

* 🌎 [Any Run](app.any.run/) - Interactive online malware analysis service for dynamic and static research of most types of threats using any environment.
* <b><code>&nbsp;&nbsp;5410⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;614🍴</code></b> [CAPA](https://github.com/mandiant/capa)) - detects capabilities in executable files. You run it against a PE, ELF, .NET module, or shellcode file and it tells you what it thinks the program can do.
* <b><code>&nbsp;&nbsp;2527⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;473🍴</code></b> [CAPEv2](https://github.com/kevoreilly/CAPEv2)) - Malware Configuration And Payload Extraction.
* <b><code>&nbsp;&nbsp;5739⭐</code></b> <b><code>&nbsp;&nbsp;1719🍴</code></b> [Cuckoo](https://github.com/cuckoosandbox/cuckoo)) - Open Source Highly configurable sandboxing tool.
* <b><code>&nbsp;&nbsp;&nbsp;401⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;177🍴</code></b> [Cuckoo-modified](https://github.com/spender-sandbox/cuckoo-modified)) - Heavily modified Cuckoo fork developed by community.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;22⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [Cuckoo-modified-api](https://github.com/keithjjones/cuckoo-modified-api)) - Python library to control a cuckoo-modified sandbox.
* <b><code>&nbsp;16882⭐</code></b> <b><code>&nbsp;&nbsp;1223🍴</code></b> [Cutter](https://github.com/rizinorg/cutter)) - Free and Open Source Reverse Engineering Platform powered by rizin.
* <b><code>&nbsp;58527⭐</code></b> <b><code>&nbsp;&nbsp;6522🍴</code></b> [Ghidra](https://github.com/NationalSecurityAgency/ghidra)) - Software Reverse Engineering Framework.
* 🌎 [Hybrid-Analysis](www.hybrid-analysis.com/) - Free powerful online sandbox by CrowdStrike.
* 🌎 [Intezer](analyze.intezer.com/#/) - Intezer Analyze dives into Windows binaries to detect micro-code similarities to known threats, in order to provide accurate yet easy-to-understand results.
* 🌎 [Joe Sandbox (Community)](www.joesandbox.com/) - Joe Sandbox detects and analyzes potential malicious files and URLs on Windows, Android, Mac OS, Linux, and iOS for suspicious activities; providing comprehensive and detailed analysis reports.
* <b><code>&nbsp;&nbsp;&nbsp;178⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;42🍴</code></b> [Mastiff](https://github.com/KoreLogicSecurity/mastiff)) - Static analysis framework that automates the process of extracting key characteristics from a number of different file formats.
* 🌎 [Metadefender Cloud](www.metadefender.com) - Free threat intelligence platform providing multiscanning, data sanitization and vulnerability assessment of files.
* <b><code>&nbsp;21940⭐</code></b> <b><code>&nbsp;&nbsp;3088🍴</code></b> [Radare2](https://github.com/radareorg/radare2)) - Reverse engineering framework and command-line toolset.
* 🌎 [Reverse.IT](www.reverse.it/) - Alternative domain for the Hybrid-Analysis tool provided by CrowdStrike.
* <b><code>&nbsp;&nbsp;2978⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;406🍴</code></b> [Rizin](https://github.com/rizinorg/rizin)) - UNIX-like reverse engineering framework and command-line toolset
* <b><code>&nbsp;&nbsp;&nbsp;724⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;124🍴</code></b> [StringSifter](https://github.com/fireeye/stringsifter)) - A machine learning tool that ranks strings based on their relevance for malware analysis.
* 🌎 [Threat.Zone](app.threat.zone) - Cloud based threat analysis platform which include sandbox, CDR and interactive analysis for researchers.
* 🌎 [Valkyrie Comodo](valkyrie.comodo.com) - Valkyrie uses run-time behavior and hundreds of features from a file to perform analysis.
* <b><code>&nbsp;&nbsp;1549⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;347🍴</code></b> [Viper](https://github.com/viper-framework/viper)) - Python based binary analysis and management framework, that works well with Cuckoo and YARA.
* 🌎 [Virustotal](www.virustotal.com) - Free online service that analyzes files and URLs enabling the identification of viruses, worms, trojans and other kinds of malicious content detected by antivirus engines and website scanners.
* <b><code>&nbsp;&nbsp;&nbsp;141⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;30🍴</code></b> [Visualize_Logs](https://github.com/keithjjones/visualize_logs)) - Open source visualization library and command line tools for logs (Cuckoo, Procmon, more to come).
* 🌎 [Yomi](yomi.yoroi.company) - Free MultiSandbox managed and hosted by Yoroi.

### Scanner Tools

* <b><code>&nbsp;&nbsp;&nbsp;744⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;110🍴</code></b> [Fenrir](https://github.com/Neo23x0/Fenrir)) - Simple IOC scanner. It allows scanning any Linux/Unix/OSX system for IOCs in plain bash. Created by the creators of THOR and LOKI.
* <b><code>&nbsp;&nbsp;3573⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;603🍴</code></b> [LOKI](https://github.com/Neo23x0/Loki)) - Free IR scanner for scanning endpoint with yara rules and other indicators(IOCs).
* <b><code>&nbsp;&nbsp;&nbsp;169⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;28🍴</code></b> [Spyre](https://github.com/spyre-project/spyre)) - Simple YARA-based IOC scanner written in Go

### Timeline Tools

* <b><code>&nbsp;&nbsp;&nbsp;923⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;112🍴</code></b> [Aurora Incident Response](https://github.com/cyb3rfox/Aurora-Incident-Response)) - Platform developed to build easily a detailed timeline of an incident.
* 🌎 [Highlighter](www.fireeye.com/services/freeware/highlighter.html) - Free Tool available from Fire/Mandiant that will depict log/text file that can highlight areas on the graphic, that corresponded to a key word or phrase. Good for time lining an infection and what was done post compromise.
* <b><code>&nbsp;&nbsp;1018⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;130🍴</code></b> [Morgue](https://github.com/etsy/morgue)) - PHP Web app by Etsy for managing postmortems.
* <b><code>&nbsp;&nbsp;1875⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;374🍴</code></b> [Plaso](https://github.com/log2timeline/plaso)) -  a Python-based backend engine for the tool log2timeline.
* <b><code>&nbsp;&nbsp;2791⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;611🍴</code></b> [Timesketch](https://github.com/google/timesketch)) - Open source tool for collaborative forensic timeline analysis.

### Videos

* 🌎 [The Future of Incident Response](www.youtube.com/watch?v=bDcx4UNpKNc) - Presented by Bruce Schneier at OWASP AppSecUSA 2015.

### Windows Evidence Collection

* <b><code>&nbsp;&nbsp;&nbsp;188⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;29🍴</code></b> [AChoir](https://github.com/OMENScan/AChoir)) - Framework/scripting tool to standardize and simplify the process of scripting live acquisition utilities for Windows.
* [Crowd Response](http://www.crowdstrike.com/community-tools/) - Lightweight Windows console application designed to aid in the gathering of system information for incident response and security engagements. It features numerous modules and output formats.
* [Cyber Triage](http://www.cybertriage.com) - Cyber Triage has a lightweight collection tool that is free to use. It collects source files (such as registry hives and event logs), but also parses them on the live host so that it can also collect the executables that the startup items, scheduled, tasks, etc. refer to. It's output is a JSON file that can be imported into the free version of Cyber Triage. Cyber Triage is made by Sleuth Kit Labs, which also makes Autopsy. 
* 🌎 [DFIR ORC](dfir-orc.github.io/) - DFIR ORC is a collection of specialized tools dedicated to reliably parse and collect critical artifacts such as the MFT, registry hives or event logs. DFIR ORC collects data, but does not analyze it: it is not meant to triage machines. It provides a forensically relevant snapshot of machines running Microsoft Windows. The code can be found on <b><code>&nbsp;&nbsp;&nbsp;416⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;45🍴</code></b> [GitHub](https://github.com/DFIR-ORC/dfir-orc)).
* <b><code>&nbsp;&nbsp;&nbsp;509⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;127🍴</code></b> [FastIR Collector](https://github.com/SekoiaLab/Fastir_Collector)) - Tool that collects different artifacts on live Windows systems and records the results in csv files. With the analyses of these artifacts, an early compromise can be detected.
* <b><code>&nbsp;&nbsp;2350⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;201🍴</code></b> [Fibratus](https://github.com/rabbitstack/fibratus)) - Tool for exploration and tracing of the Windows kernel.
* <b><code>&nbsp;&nbsp;&nbsp;202⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;20🍴</code></b> [Hoarder](https://github.com/muteb/Hoarder)) - Collecting the most valuable artifacts for forensics or incident response investigations.
* 🌎 [IREC](binalyze.com/products/irec-free/) - All-in-one IR Evidence Collector which captures RAM Image, $MFT, EventLogs, WMI Scripts, Registry Hives, System Restore Points and much more. It is FREE, lightning fast and easy to use.
* <b><code>&nbsp;&nbsp;&nbsp;148⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;29🍴</code></b> [Invoke-LiveResponse](https://github.com/mgreen27/Invoke-LiveResponse)) -  Invoke-LiveResponse is a live response tool for targeted collection.
* 🌎 [IOC Finder](www.fireeye.com/services/freeware/ioc-finder.html) - Free tool from Mandiant for collecting host system data and reporting the presence of Indicators of Compromise (IOCs). Support for Windows only. No longer maintained. Only fully supported up to Windows 7 / Windows Server 2008 R2.
* <b><code>&nbsp;&nbsp;&nbsp;134⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;23🍴</code></b> [IRTriage](https://github.com/AJMartel/IRTriage)) - Incident Response Triage - Windows Evidence Collection for Forensic Analysis.
* 🌎 [KAPE](www.kroll.com/en/services/cyber-risk/incident-response-litigation-support/kroll-artifact-parser-extractor-kape) - Kroll Artifact Parser and Extractor (KAPE) by Eric Zimmerman. A triage tool that finds the most prevalent digital artifacts and then parses them quickly. Great and thorough when time is of the essence.
* <b><code>&nbsp;&nbsp;3573⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;603🍴</code></b> [LOKI](https://github.com/Neo23x0/Loki)) - Free IR scanner for scanning endpoint with yara rules and other indicators(IOCs).
* <b><code>&nbsp;&nbsp;&nbsp;461⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;85🍴</code></b> [MEERKAT](https://github.com/TonyPhipps/Meerkat)) - PowerShell-based triage and threat hunting for Windows.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;40⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;7🍴</code></b> [Panorama](https://github.com/AlmCo/Panorama)) - Fast incident overview on live Windows systems.
* <b><code>&nbsp;&nbsp;1403⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;277🍴</code></b> [PowerForensics](https://github.com/Invoke-IR/PowerForensics)) - Live disk forensics platform, using PowerShell.
* <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;?🍴</code></b> [PSRecon](https://github.com/gfoss/PSRecon/)) - PSRecon gathers data from a remote Windows host using PowerShell (v2 or later), organizes the data into folders, hashes all extracted data, hashes PowerShell and various system properties, and sends the data off to the security team. The data can be pushed to a share, sent over email, or retained locally.
* <b><code>&nbsp;&nbsp;&nbsp;619⭐</code></b> <b><code>&nbsp;&nbsp;&nbsp;137🍴</code></b> [RegRipper](https://github.com/keydet89/RegRipper3.0)) - Open source tool, written in Perl, for extracting/parsing information (keys, values, data) from the Registry and presenting it for analysis.

## Source
<b><code>&nbsp;&nbsp;8267⭐</code></b> <b><code>&nbsp;&nbsp;1585🍴</code></b> [meirwah/awesome-incident-response](https://github.com/meirwah/awesome-incident-response))