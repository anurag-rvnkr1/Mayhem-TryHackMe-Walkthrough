
---
layout: default
title: "Mayhem — TryHackMe DFIR Investigation"
description: "A Digital Forensics and Incident Response investigation of Havoc Command and Control, covering PCAP analysis, PowerShell malware delivery, AES-CTR traffic decryption, Windows artifact recovery, and Blue Team detection engineering."
---

<div class="ctf-hero">

  <h1>Mayhem — DFIR Investigation</h1>

  <p>
    A Blue Team incident investigation documenting the reconstruction of a
    Havoc Command and Control compromise through network forensics, malware
    triage, protocol analysis, cryptographic traffic decryption, and Windows
    artifact recovery.
  </p>

  <div class="ctf-badges">
    <span class="ctf-badge">TryHackMe</span>
    <span class="ctf-badge">Blue Team</span>
    <span class="ctf-badge">DFIR</span>
    <span class="ctf-badge">Network Forensics</span>
    <span class="ctf-badge">Havoc C2</span>
    <span class="ctf-badge">Threat Hunting</span>
  </div>

</div>

![Mayhem investigation cover](assets/01_cover_mayhem.png)

## Investigation Summary

This case study documents the investigation of a simulated Windows endpoint compromise using the supplied packet capture, `traffic.pcapng`.

The investigation reconstructs the observed delivery of a PowerShell downloader, extraction and static analysis of a masquerading executable, identification of the Havoc Demon framework, analysis of the `DEMON_INIT` registration packet, AES-CTR session recovery, decryption of command-and-control traffic, and reconstruction of Windows reconnaissance, persistence, and file-discovery activity.

The investigation relies on network evidence and recovered artifacts rather than executing the malware.

<div class="ctf-card-grid">

  <div class="ctf-card">
    <div class="ctf-card-title">Platform</div>
    <div class="ctf-card-value">TryHackMe — Mayhem</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Investigation Type</div>
    <div class="ctf-card-value">Digital Forensics and Incident Response</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Primary Evidence</div>
    <div class="ctf-card-value">traffic.pcapng</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Malware Framework</div>
    <div class="ctf-card-value">Havoc Demon</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Cryptographic Analysis</div>
    <div class="ctf-card-value">AES-CTR</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Investigation Status</div>
    <div class="ctf-card-value">Completed in the documented lab</div>
  </div>

</div>

<div class="key-finding">

  <div class="key-finding-title">Primary Finding</div>

  The packet capture contains an HTTP-based malware delivery sequence followed
  by encrypted Havoc command-and-control communication. Reconstructing the
  HTTP streams, examining the executable statically, identifying the
  registration packet, and recovering the documented AES session material
  makes it possible to investigate the endpoint's subsequent activity.

</div>

## Navigation

<div class="ctf-toc">

<div class="ctf-toc-title">Documentation Map</div>

- [Mission and Investigation Objectives](#mission-and-investigation-objectives)
- [Target and Lab Information](#target-and-lab-information)
- [Scope and Responsible Use](#scope-and-responsible-use)
- [Investigation Methodology](#investigation-methodology)
- [Tools Used](#tools-used)
- [Repository Structure](#repository-structure)
- [Attack Infrastructure and Network Topology](#attack-infrastructure-and-network-topology)
- [Evidence Collection and Preservation](#evidence-collection-and-preservation)
- [Phase 01 — Network Forensics](#phase-01--network-forensics)
- [Phase 02 — Conversation Isolation](#phase-02--conversation-isolation)
- [Phase 03 — PowerShell Delivery Chain](#phase-03--powershell-delivery-chain)
- [Phase 04 — HTTP Object Extraction](#phase-04--http-object-extraction)
- [Phase 05 — Malware Static Analysis](#phase-05--malware-static-analysis)
- [Phase 06 — Havoc Command and Control](#phase-06--havoc-command-and-control)
- [Phase 07 — DEMON_INIT Registration Analysis](#phase-07--demon_init-registration-analysis)
- [Phase 08 — AES-CTR Session Recovery](#phase-08--aes-ctr-session-recovery)
- [Phase 09 — CyberChef Decryption](#phase-09--cyberchef-decryption)
- [Phase 10 — Windows Artifact Reconstruction](#phase-10--windows-artifact-reconstruction)
- [Phase 11 — Windows Identity Enumeration](#phase-11--windows-identity-enumeration)
- [Phase 12 — Network Configuration Discovery](#phase-12--network-configuration-discovery)
- [Phase 13 — Reconnaissance Correlation](#phase-13--reconnaissance-correlation)
- [Phase 14 — Persistence Investigation](#phase-14--persistence-investigation)
- [Phase 15 — Sensitive File Discovery](#phase-15--sensitive-file-discovery)
- [Phase 16 — Sensitive File Access](#phase-16--sensitive-file-access)
- [Phase 17 — Indicators of Compromise](#phase-17--indicators-of-compromise)
- [Incident Timeline Reconstruction](#incident-timeline-reconstruction)
- [Evidence Correlation Matrix](#evidence-correlation-matrix)
- [MITRE ATT&CK Mapping](#mitre-attck-mapping)
- [Detection Engineering](#detection-engineering)
- [Threat Hunting Playbook](#threat-hunting-playbook)
- [Detection Coverage Matrix](#detection-coverage-matrix)
- [Security Findings](#security-findings)
- [Defensive Recommendations](#defensive-recommendations)
- [Lessons Learned](#lessons-learned)
- [Skills Demonstrated](#skills-demonstrated)
- [Learning Outcomes](#learning-outcomes)
- [References](#references)
- [Responsible Use](#responsible-use)
- [Conclusion](#conclusion)

</div>

## Mission and Investigation Objectives

The objective of the Mayhem investigation is to reconstruct a simulated malware incident from network evidence and translate the findings into actionable defensive insights.

Unlike a conventional exploitation-focused CTF, this exercise emphasizes forensic reasoning, evidence correlation, protocol understanding, and the reconstruction of post-compromise activity.

### Investigation objectives

- Identify the suspicious communication between the Windows endpoint and the server.
- Reconstruct HTTP streams to recover the PowerShell downloader.
- Extract the transferred executable without executing it.
- Perform static malware triage and correlate findings with threat intelligence.
- Identify Havoc Demon command-and-control activity.
- Analyze the `DEMON_INIT` registration packet and its documented protocol fields.
- Investigate AES-CTR session recovery and encrypted HTTP traffic.
- Recover Windows identity, network configuration, persistence, and file-discovery artifacts.
- Build an incident timeline and document relevant indicators of compromise.
- Translate observed behavior into detection engineering and threat-hunting opportunities.

### Investigation success criteria

The investigation is considered complete within the documented lab workflow when the delivery chain, malware attribution, command-and-control registration, cryptographic analysis, and subsequent Windows activity can be correlated using the available evidence.

## Target and Lab Information

<div class="ctf-card-grid">

  <div class="ctf-card">
    <div class="ctf-card-title">Victim Endpoint</div>
    <div class="ctf-card-value">10.0.2.38</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Suspicious Server</div>
    <div class="ctf-card-value">10.0.2.37</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Evidence File</div>
    <div class="ctf-card-value">traffic.pcapng</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Primary Protocol</div>
    <div class="ctf-card-value">HTTP</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Command and Control</div>
    <div class="ctf-card-value">Havoc Demon</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Encryption</div>
    <div class="ctf-card-value">AES-CTR</div>
  </div>

</div>

The investigation identifies `10.0.2.38` as the compromised Windows workstation and `10.0.2.37` as the suspicious HTTP server and Havoc infrastructure described in the original documentation.

The original evidence also identifies TCP port `1337` as an executable-delivery service.

These addresses and the port are lab indicators. They should not be treated as universal Havoc indicators or as evidence of malicious activity outside this environment.

## Scope and Responsible Use

The investigation is restricted to the TryHackMe lab evidence and artifacts documented in this repository.

The original workflow includes:

- Network packet analysis.
- HTTP stream reconstruction.
- Static examination of an extracted executable.
- Threat-intelligence correlation.
- Analysis of Havoc protocol structures.
- Cryptographic traffic analysis.
- Reconstruction of Windows artifacts from decrypted network responses.
- Development of defensive monitoring and hunting ideas.

The documented workflow does not require executing the recovered malware.

Sensitive challenge artifacts remain intentionally redacted, including:

- Challenge flags and final challenge answers.
- User credentials and passwords.
- Windows SID values.
- IPv6 values.
- AES session keys.
- Initialization vectors.
- Persistence credentials.

Where the original documentation withheld a value, that redaction is preserved.

## Investigation Methodology

The investigation follows an evidence-driven DFIR workflow.

<div class="attack-chain">
  <div class="attack-step">Evidence Collection</div>
  <div class="attack-arrow">→</div>
  <div class="attack-step">Preservation</div>
  <div class="attack-arrow">→</div>
  <div class="attack-step">Examination</div>
  <div class="attack-arrow">→</div>
  <div class="attack-step">Analysis</div>
  <div class="attack-arrow">→</div>
  <div class="attack-step">Correlation</div>
  <div class="attack-arrow">→</div>
  <div class="attack-step">Reporting</div>
  <div class="attack-arrow">→</div>
  <div class="attack-step">Detection Engineering</div>
</div>

### Investigation phases

| Phase | Activity |
|---|---|
| 01 | Packet capture triage |
| 02 | TCP conversation isolation |
| 03 | HTTP stream reconstruction |
| 04 | HTTP object extraction |
| 05 | Static malware triage and attribution |
| 06 | Havoc protocol investigation |
| 07 | Registration packet analysis |
| 08 | AES session recovery |
| 09 | Encrypted traffic decryption |
| 10 | Windows artifact reconstruction |
| 11–16 | Identity, network, persistence, and file investigation |
| 17 | IOC extraction and correlation |
| 18–20 | ATT&CK mapping, detection engineering, and threat hunting |

### Evidence-handling principles

- Treat the original packet capture as the primary evidence source.
- Reconstruct network conversations before drawing conclusions.
- Extract files for static analysis rather than executing suspicious binaries.
- Correlate malware attribution across multiple documented evidence sources.
- Separate observed behavior from analyst interpretation.
- Preserve sensitive values according to the repository's redaction policy.
- Use the findings to develop defensive controls and monitoring opportunities.

## Tools Used

Only tools identified in the original investigation are listed below.

| Tool | Documented purpose |
|---|---|
| Wireshark | PCAP examination, TCP conversation analysis, HTTP stream reconstruction, and HTTP object export |
| CyberChef | Hex processing and AES-CTR decryption |
| `strings` | Static string extraction from the recovered executable |
| VirusTotal | Threat-intelligence correlation and malware-family attribution |
| PowerShell analysis | Examination of the recovered downloader and its execution behavior |
| Sysmon | Endpoint telemetry and process/network event investigation concepts |
| Splunk | SIEM hunting and event correlation examples |
| Suricata | Network intrusion-detection concepts |
| Sigma | Detection-rule concepts for suspicious endpoint behavior |

## Repository Structure

The original repository contains documentation, supporting notes, screenshots, and the GitHub Pages documentation site.

```text
Mayhem--TryHackMe-Walkthrough/
├── README.md
├── SECURITY.md
├── CONTRIBUTING.md
├── Documentation/
│   ├── Documentation.md
│   └── Documentation.docx
├── Resources/
│   └── notes.md
├── Screenshots/
│   ├── 01_room_banner.png
│   ├── 02_pcap_overview.png
│   ├── 03_http_install_ps1.png
│   ├── 04_http_object_export.png
│   ├── 05_strings_analysis.png
│   ├── 06_virustotal_analysis.png
│   ├── 07_havoc_init_packet.png
│   ├── 08_aes_key_iv.png
│   ├── 09_cyberchef_decryption.png
│   ├── 10_decrypted_metadata.png
│   ├── 11_sid_artifact.png
│   ├── 12_ipv6_artifact.png
│   ├── 13_persistence_artifact.png
│   ├── 14_flag_artifact.png
│   ├── 15_clients_csv_artifact.png
│   └── 16_answer_validation.png
└── docs/
    ├── index.md
    └── assets/
        ├── css/
        │   ├── custom.scss
        │   └── custom.css
        └── images/
```

The repository tree is retained as documented. The screenshot filenames above belong to the repository's `Screenshots/` directory; the existing Markdown image references below are preserved separately and have not been rewritten to point to different files.

## Attack Infrastructure and Network Topology

The original investigation reconstructs an internal lab network containing a Windows workstation, an HTTP server, and a Havoc command-and-control session.

```text
                 INTERNAL LAB NETWORK

          ┌─────────────────────────────┐
          │    Windows Workstation      │
          │        10.0.2.38            │
          │                             │
          │  PowerShell downloader      │
          │  Havoc Demon execution      │
          └──────────────┬──────────────┘
                         │
                         │ HTTP GET
                         │ install.ps1
                         │ notepad.exe
                         ▼
          ┌─────────────────────────────┐
          │     HTTP Server / C2        │
          │        10.0.2.37            │
          │                             │
          │  Python HTTP server         │
          │  Havoc Teamserver listener  │
          └──────────────┬──────────────┘
                         │
                         │ Encrypted HTTP POST
                         │ AES-CTR traffic
                         ▼
               Havoc C2 communication
```

### Documented network indicators

| Indicator | Interpretation |
|---|---|
| `10.0.2.38` | Compromised Windows workstation |
| `10.0.2.37` | Suspicious HTTP server and Havoc infrastructure |
| TCP `1337` | Documented executable-delivery service |
| HTTP GET | Downloader and executable retrieval |
| HTTP POST | Havoc beacon communication |
| AES-CTR | Encryption associated with the analyzed C2 traffic |

The addresses and service descriptions are taken from the original case study. The investigation uses them to isolate the relevant conversation and reconstruct the documented incident.

## Evidence Collection and Preservation

### Primary evidence

`traffic.pcapng`

The packet capture provides the foundation for the investigation. The original workflow examines network traffic, reconstructs HTTP streams, exports transferred objects, and analyzes encrypted command-and-control communication.

### Evidence sources

- Original packet capture.
- TCP conversations.
- HTTP request and response streams.
- Exported HTTP objects.
- Static executable strings.
- Threat-intelligence results.
- Havoc registration packet.
- Decrypted registration metadata.
- Decrypted Windows command responses.
- Existing screenshots and supporting documentation.

### Evidence workflow

<div class="attack-chain">
  <div class="attack-step">Original PCAP</div>
  <div class="attack-arrow">→</div>
  <div class="attack-step">HTTP Streams</div>
  <div class="attack-arrow">→</div>
  <div class="attack-step">Extracted Objects</div>
  <div class="attack-arrow">→</div>
  <div class="attack-step">Static Analysis</div>
  <div class="attack-arrow">→</div>
  <div class="attack-step">Protocol Analysis</div>
  <div class="attack-arrow">→</div>
  <div class="attack-step">Artifact Recovery</div>
</div>

## Phase 01 — Network Forensics

The first phase establishes a timeline using network telemetry before attributing the executable or interpreting encrypted traffic.

### Investigation questions

| Question | Evidence source |
|---|---|
| Which endpoint is compromised? | TCP conversations and HTTP requests |
| Which server delivered the payload? | HTTP streams and destination addresses |
| How was the malware transferred? | HTTP object export |
| Where does the delivery sequence begin? | PowerShell download request |
| Which traffic represents potential C2 activity? | Repeated HTTP POST requests and timeline correlation |

### Evidence 01 — Packet Capture Overview

![PCAP Overview](assets/02_pcap_overview.png)

<figure>
  <figcaption>Figure 02 — Initial Wireshark packet capture. The investigation starts by reviewing TCP conversations and identifying the communication sequence associated with payload delivery and subsequent encrypted traffic.</figcaption>
</figure>

### Initial observations

| Observation | Forensic interpretation |
|---|---|
| TCP FIN packets | Connection teardown; not independently indicative of compromise |
| New TCP handshake | Establishes a candidate communication session |
| HTTP requests | Potential evidence of payload delivery |
| Binary file transfer | Requires examination to determine the transferred content |
| Repeated HTTP POST requests | Candidate beacon traffic requiring correlation with the malware execution sequence |

### Reducing investigation noise

The original investigation prioritizes HTTP transactions and suspicious binary traffic rather than examining unrelated connection-termination packets first.

TCP FIN/ACK packets and unrelated retransmissions may be deprioritized during initial triage, but should not be discarded when they become relevant to timing, retransmission analysis, or connection reconstruction.

The goal is to identify the suspicious conversation while retaining the ability to revisit the complete packet capture.

## Phase 02 — Conversation Isolation

The original investigation isolates traffic between the two documented hosts.

### Wireshark display filter

```wireshark
ip.addr == 10.0.2.38 && ip.addr == 10.0.2.37
```

The filter limits the displayed packets to communications involving both `10.0.2.38` and `10.0.2.37`.

This helps focus the investigation on the relevant TCP sessions and simplifies timeline reconstruction.

### Conversation summary

| Host | Observed behavior |
|---|---|
| `10.0.2.38` | Requests the PowerShell installer and executable payload |
| `10.0.2.37` | Serves the PowerShell script and executable payload |

### TCP session reconstruction

```text
10.0.2.38                         10.0.2.37

   SYN  ─────────────────────────────►

        ◄──────────────────── SYN, ACK

   ACK  ─────────────────────────────►

   GET /install.ps1 ─────────────────►

   HTTP 200 OK  ◄─────────────────────

   GET /notepad.exe ─────────────────►

   HTTP 200 OK  ◄─────────────────────
```

The HTTP requests become the primary investigation pivot because they establish a documented relationship between the workstation, the server, and the transferred artifacts.

## Phase 03 — PowerShell Delivery Chain

![HTTP PowerShell](assets/03_http_install_ps1.png)

<figure>
  <figcaption>Figure 03 — HTTP stream reconstruction. Wireshark's Follow HTTP Stream functionality is used to examine the PowerShell script transmitted in the recorded conversation.</figcaption>
</figure>

### HTTP stream recovery

The documented workflow uses Wireshark to reconstruct the application-level conversation:

```text
Select relevant packet
        |
        v
Right-click
        |
        v
Follow
        |
        v
HTTP Stream
        |
        v
Examine recovered script
```

### Suspicious request

```http
GET /install.ps1 HTTP/1.1
```

This request identifies the retrieval of `install.ps1`, the PowerShell downloader documented in the original investigation.

### Why the request matters

| Evidence | Investigation value |
|---|---|
| PowerShell script retrieval | Identifies a potential downloader stage |
| HTTP GET request | Establishes the file retrieval mechanism |
| Destination server | Provides an infrastructure correlation point |
| User-Agent information | May help characterize the client making the request |

The request is not evaluated in isolation. Its significance comes from its relationship to the later executable transfer and subsequent Havoc communication.

### PowerShell execution behavior

The original analysis documents a delivery sequence in which a PowerShell script retrieves an executable, writes it to a Downloads directory, and launches it.

```text
PowerShell downloader
        |
        v
Retrieve executable
        |
        v
Write file to Downloads
        |
        v
Launch executable
```

The documented PowerShell components include:

| Component | Investigative relevance |
|---|---|
| `Invoke-WebRequest` | HTTP retrieval functionality |
| `System.Net.WebClient` | .NET download functionality identified in the original analysis |
| `DownloadFile()` | Saves downloaded content to a local file |
| `Start-Process` | Starts a process using the specified executable |

These are legitimate Windows and PowerShell capabilities. Their presence alone does not establish malicious activity; the incident context, download source, payload, execution path, and subsequent communications provide the relevant correlation.

### Initial delivery indicators

| IOC | Documented value |
|---|---|
| Remote server | `10.0.2.37` |
| Protocol | HTTP |
| Destination directory | Downloads |
| Payload filename | `notepad.exe` |

The original analysis associates the observed PowerShell behavior with MITRE ATT&CK technique **T1059.001 — PowerShell**.

## Phase 04 — HTTP Object Extraction

![HTTP Export](assets/04_http_object_export.png)

<figure>
  <figcaption>Figure 04 — HTTP object export. Transferred objects are recovered from the packet capture for examination without executing the suspected malware.</figcaption>
</figure>

### Export workflow

```text
Wireshark
    |
    v
File
    |
    v
Export Objects
    |
    v
HTTP
    |
    v
Review recovered objects
```

### Recovered objects

| Artifact | Investigative purpose |
|---|---|
| `install.ps1` | PowerShell downloader analysis |
| `notepad.exe` | Static analysis of the delivered executable |

### Evidence preservation considerations

The original workflow recommends extracting suspicious files before analyzing them.

1. Export the object from the relevant HTTP conversation.
2. Preserve the original evidence.
3. Hash the recovered file when performing a formal investigation.
4. Conduct static analysis.
5. Correlate available threat intelligence.
6. Use a suitable isolated sandbox only when necessary and authorized.

The original documentation does not provide specific hash values, so none are added here.

Static analysis reduces the risk associated with executing an unknown binary and keeps the investigation focused on the supplied evidence.

## Phase 05 — Malware Static Analysis

![Strings Analysis](assets/05_strings_analysis.png)

<figure>
  <figcaption>Figure 05 — Static string investigation of the extracted executable.</figcaption>
</figure>

### Strings examination

The documented command is:

```bash
strings notepad.exe
```

This command extracts printable strings from the executable. It can reveal useful indicators, including embedded names, error messages, library references, and other recognizable text.

The output must be interpreted as one source of evidence rather than a complete explanation of the binary's behavior.

### Interesting artifacts

| Artifact | Interpretation |
|---|---|
| `demon.x64.exe` | Framework-related string supporting the Havoc attribution |
| Windows API strings | May indicate capabilities associated with Windows execution or communication |
| Embedded metadata | Provides additional material for static examination |

### Analyst assessment

The filename `notepad.exe` is deceptive in the documented context. The original investigation identifies the executable as a Havoc Demon payload rather than assuming that its filename identifies its true purpose.

The original case study associates this behavior with **T1036 — Masquerading**.

The relevant evidence is the discrepancy between the executable's apparent identity and the malware-related artifacts recovered during analysis.

### Threat-intelligence correlation

![VirusTotal](assets/06_virustotal_analysis.png)

<figure>
  <figcaption>Figure 06 — Threat-intelligence correlation used in the original investigation to support the Havoc C2 attribution.</figcaption>
</figure>

The original investigation reports the following intelligence findings:

| Category | Documented observation |
|---|---|
| Malware family | Havoc Demon |
| Classification | Trojan / backdoor |
| Behavior | Command-and-control framework |
| Delivery | HTTP |

The attribution is based on the combined investigation of the packet capture, extracted executable, static strings, and the documented VirusTotal analysis.

The original documentation does not include a file hash or a specific VirusTotal report URL. Neither is invented in this rewrite.

## Phase 06 — Havoc Command and Control

After identifying the executable as a Havoc Demon payload, the investigation turns to the structure of its network communication.

### Investigation objectives

- Understand the documented Havoc components.
- Identify the initial registration packet.
- Examine protocol header fields.
- Investigate AES session key and IV recovery.
- Decrypt selected HTTP traffic.
- Recover the endpoint metadata and subsequent activity described in the original case study.

### Havoc architecture

```text
             Havoc command-and-control architecture

             ┌───────────────────────────┐
             │      Operator client      │
             │     Management GUI        │
             └─────────────┬─────────────┘
                           |
                           v
             ┌───────────────────────────┐
             │      Havoc Teamserver      │
             │      HTTP listener         │
             └─────────────┬─────────────┘
                           |
                 Encrypted HTTP traffic
                           |
                           v
             ┌───────────────────────────┐
             │       Havoc Demon          │
             │ Compromised workstation    │
             └───────────────────────────┘
```

### Components

| Component | Documented role |
|---|---|
| Operator client | Issues commands through the Teamserver |
| Teamserver | Manages the command-and-control infrastructure and listener |
| Demon agent | Executes tasks on the compromised endpoint |
| Victim workstation | Generates the observed beacon traffic |

### Beacon lifecycle

The original investigation describes the following communication sequence:

```text
Demon agent
     |
     v
DEMON_INIT registration
     |
     v
Registration response
     |
     v
Beacon check-in
     |
     v
Encrypted task delivery
     |
     v
Command execution and output
     |
     v
Continued beacon communication
```

The registration packet is particularly important because the original analysis identifies it as the location where the cryptographic material required for subsequent traffic analysis can be recovered.

## Phase 07 — DEMON_INIT Registration Analysis

![Havoc Registration Packet](assets/07_havoc_init_packet.png)

<figure>
  <figcaption>Figure 07 — Havoc registration packet analysis. The original investigation identifies the first relevant registration request after payload execution as DEMON_INIT.</figcaption>
</figure>

### Why the registration packet matters

The original analysis identifies the following protocol artifacts:

| Artifact | Investigative purpose |
|---|---|
| Agent identifier | Associates communication with a Demon session |
| Magic bytes | Helps identify the protocol structure |
| AES session key | Used in the documented traffic decryption workflow |
| Initialization vector | Used to initialize the AES-CTR operation |

Sensitive cryptographic values remain redacted.

### Documented request header

The original documentation describes a 20-byte request header:

```text
┌────────────────────────────────────────────────────────────┐
│                 HAVOC REQUEST HEADER                       │
├────────────┬────────────┬────────────┬───────────┬──────────┤
│ Size       │ Magic      │ Agent ID   │ Command   │ Memory ID│
│ 4 bytes    │ 4 bytes    │ 4 bytes    │ 4 bytes   │ 4 bytes  │
└────────────┴────────────┴────────────┴───────────┴──────────┘
```

The documented fields are:

| Field | Description |
|---|---|
| Payload size | Length information for the protocol payload |
| Magic bytes | Protocol-identification field |
| Agent ID | Identifier associated with the Demon session |
| Command ID | Field used to distinguish packet purpose |
| Memory ID | Additional protocol or session metadata |

The original analysis associates command ID `99` with `DEMON_INIT` registration and command ID `1` with Get Job / beacon activity.

These mappings are retained as documented observations from this investigation.

### Command ID observations

| Command ID | Original interpretation |
|---|---|
| `99` | `DEMON_INIT` registration |
| `1` | Get Job / beacon |
| Other values | Additional command or task activity requiring protocol interpretation |

The command ID is useful as an investigation pivot, but the interpretation of a packet should also account for its structure, direction, context, and associated traffic.

### Registration packet evidence

![AES Key & IV Extraction](assets/08_aes_key_iv.png)

<figure>
  <figcaption>Figure 08 — Hex-level registration packet analysis and the documented identification of the session cryptographic fields.</figcaption>
</figure>

The original investigation documents the following layout:

```text
Offset 0x00
    |
    v
Payload size

Offset 0x04
    |
    v
Magic bytes

Offset 0x08
    |
    v
Agent identifier

Offset 0x0C
    |
    v
Command ID

Offset 0x10
    |
    v
Memory ID

Offset 0x14
    |
    v
AES session key

Offset 0x34
    |
    v
Initialization vector

    |
    v
Registration metadata
```

The figure and offsets are retained from the supplied documentation. The actual session key, IV, and sensitive values are intentionally not reproduced.

## Phase 08 — AES-CTR Session Recovery

The original investigation identifies AES in Counter mode (CTR) as the encryption mechanism used in the analyzed Havoc communication.

### Documented encryption characteristics

| Property | Documented value |
|---|---|
| Algorithm | AES |
| Mode | CTR |
| Key size | 32 bytes |
| IV size | 16 bytes |
| Input representation | Hexadecimal stream |

### Redacted session material

The original repository intentionally withholds the recovered values.

```text
AES session key:
[REDACTED]

Initialization vector:
[REDACTED]
```

These redactions are preserved.

### How AES-CTR works

AES-CTR generates a keystream from successive counter blocks. The keystream is combined with the input data using XOR.

```text
Initialization vector / counter
              |
              v
         AES operation
              |
              v
          Keystream
              |
              v
       XOR with ciphertext
              |
              v
           Plaintext
```

Correct decryption requires the appropriate key, counter initialization, and byte alignment.

CTR mode does not authenticate the ciphertext by itself. Therefore, successful processing is not sufficient proof that the output is meaningful; the recovered structure and content must also be validated against the expected protocol and investigation context.

### Investigation lesson

Understanding the protocol framing is as important as identifying the encryption algorithm. Incorrectly including header bytes or using the wrong offset can result in output that cannot be interpreted correctly.

## Phase 09 — CyberChef Decryption

![CyberChef Workflow](assets/09_cyberchef_decryption.png)

<figure>
  <figcaption>Figure 09 — CyberChef workflow used in the original investigation to decrypt selected Havoc traffic.</figcaption>
</figure>

### Decryption workflow

```text
Wireshark File Data
        |
        v
Copy hexadecimal stream
        |
        v
Identify protocol header
        |
        v
Separate encrypted payload
        |
        v
Configure AES-CTR
        |
        v
Inspect recovered output
        |
        v
Validate metadata structure
```

### Documented CyberChef configuration

| Setting | Value |
|---|---|
| Operation | AES Decrypt |
| Mode | CTR |
| Input | Hexadecimal |
| Output | Raw |
| Key | Recovered session key, redacted |
| IV | Recovered initialization vector, redacted |

### Protocol header offsets

The original investigation records different header lengths for requests and responses.

| Traffic type | Header length to remove before decryption |
|---|---:|
| HTTP POST request | 20 bytes, or 40 hexadecimal characters |
| HTTP response | 12 bytes, or 24 hexadecimal characters |

These offsets are retained from the source documentation. They apply to the specific protocol framing described in the original case study; they should not be generalized to every HTTP packet or every Havoc implementation without verification.

<div class="key-finding">

  <div class="key-finding-title">Critical Forensic Finding</div>

  The original analysis reports that attempting to decrypt the complete File
  Data field fails because the protocol header is not part of the encrypted
  payload. Correctly separating the documented header from the encrypted
  content is essential to the workflow.

</div>

### Recovered metadata

![Decrypted Metadata](assets/10_decrypted_metadata.png)

<figure>
  <figcaption>Figure 10 — Decrypted registration metadata from the original investigation.</figcaption>
</figure>

The original documentation reports recovery of structured Windows endpoint metadata, including:

| Artifact | Investigative value |
|---|---|
| Hostname | Endpoint identification |
| Username | Compromised user context |
| Operating system | Platform identification |
| Architecture | Endpoint architecture context |
| Process metadata | Information about the Demon execution environment |

The original validation checklist records that the registration packet was located, the key and IV were identified, the protocol header was removed, and the metadata was decoded.

### Beacon traffic analysis

After registration, the original investigation describes repeated HTTP POST requests and encrypted responses.

| Observed behavior | Blue Team interpretation |
|---|---|
| Repeated POST requests | Candidate beacon or heartbeat communication |
| Small binary payloads | Potential task polling or protocol messages |
| Fixed destination | Infrastructure correlation opportunity |
| Encrypted responses | Requires protocol-aware analysis |

Not every POST request necessarily represents an executed attacker command. Some traffic may be routine beacon or heartbeat communication. Distinguishing these message types helps reduce investigative noise.

## Phase 10 — Windows Artifact Reconstruction

After the documented traffic decryption, the investigation moves from network-level evidence to the Windows activity represented in the recovered responses.

The original case study describes recovery of:

- Windows identity information.
- Hostname and user context.
- SID-related evidence.
- IPv6 and network configuration information.
- Local account creation.
- Filesystem discovery.
- A sensitive business CSV file.

### Artifact categories

<div class="ctf-card-grid">

  <div class="ctf-card">
    <div class="ctf-card-title">Identity</div>
    <div class="ctf-card-value">Hostname, username, SID</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Networking</div>
    <div class="ctf-card-value">IPv6 and adapter discovery</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Persistence</div>
    <div class="ctf-card-value">Local account creation</div>
  </div>

  <div class="ctf-card">
    <div class="ctf-card-title">Filesystem</div>
    <div class="ctf-card-value">Discovery of clients.csv</div>
  </div>

</div>

### Documented execution flow

```text
Havoc Teamserver
       |
       v
Encrypted command
       |
       v
Demon agent
       |
       v
Windows command execution
       |
       v
Command output
       |
       v
Encrypted response
       |
       v
Forensic recovery
```

The following sections preserve the specific artifact categories and redactions documented in the source.

## Phase 11 — Windows Identity Enumeration

![SID Artifact](assets/11_sid_artifact.png)

<figure>
  <figcaption>Figure 11 — Windows SID artifact recovered during the original investigation.</figcaption>
</figure>

### Why a SID matters

A Windows Security Identifier (SID) identifies a security principal, such as a user or group.

During an investigation, SID information can help correlate:

- User and group identities.
- Windows security events.
- File ownership.
- Registry and system artifacts.
- Authentication activity.

The original documentation reports that identity information was recovered from the compromised endpoint.

### Artifact interpretation

| Artifact | Investigation context |
|---|---|
| Windows SID | Security-principal identification |
| Hostname | Endpoint identification |
| Username | User context associated with the endpoint |

### Redaction

```text
Windows SID:
[REDACTED]
```

The original SID is intentionally withheld.

## Phase 12 — Network Configuration Discovery

![IPv6 Artifact](assets/12_ipv6_artifact.png)

<figure>
  <figcaption>Figure 12 — Network configuration artifact from the original investigation.</figcaption>
</figure>

The original analysis reports network discovery activity involving IPv4, IPv6, network adapters, and DNS-related configuration.

### Documented artifacts

| Artifact | Investigative purpose |
|---|---|
| IPv4 configuration | Host addressing |
| IPv6 configuration | Interface and address discovery |
| Network adapter details | Endpoint network context |
| DNS information | Name-resolution and environment context |

The original documentation associates this activity with **T1016 — System Network Configuration Discovery**.

### IPv6 redaction

```text
IPv6 address:
[REDACTED]
```

The original IPv6 value remains withheld.

### Forensic value

Network configuration can help investigators understand which interfaces and addresses were visible to the compromised endpoint. It may also provide useful context when correlating the endpoint with network logs and other evidence.

The presence of IPv6 or multiple network interfaces is not inherently malicious; its significance depends on the surrounding behavior.

## Phase 13 — Reconnaissance Correlation

The original investigation documents a sequence of endpoint-identification and network-discovery activities.

```text
Havoc registration
        |
        v
Hostname enumeration
        |
        v
Username enumeration
        |
        v
SID-related investigation
        |
        v
IPv6 configuration discovery
        |
        v
Environment mapping
```

### Observed behavior

| Activity | Blue Team interpretation |
|---|---|
| Hostname recovery | Identifies the endpoint |
| Username recovery | Establishes user context |
| SID enumeration | Provides identity information |
| Network configuration discovery | Reveals endpoint networking context |

This sequence supports reconstruction of post-compromise reconnaissance. The exact ordering of individual commands should be established from packet timestamps and decrypted messages when those details are available.

## Phase 14 — Persistence Investigation

![Persistence Artifact](assets/13_persistence_artifact.png)

<figure>
  <figcaption>Figure 13 — Persistence-related artifact documenting local Windows account creation.</figcaption>
</figure>

The original investigation reports that the attacker created a new local Windows user account.

### Why account creation matters

An unauthorized local account can provide an additional authentication path and may allow continued access beyond the initial malware execution.

Its actual privileges and persistence impact depend on the account configuration, group membership, credentials, and host policy.

### Documented activity

```text
Reconnaissance
       |
       v
Local account creation
       |
       v
Continued command-and-control activity
```

### ATT&CK mapping

The original documentation associates the activity with **T1136 — Create Account**.

### Redacted credentials

```text
Persistence username:
[REDACTED]

Persistence password:
[REDACTED]
```

The credentials are intentionally withheld.

### Windows event investigation

The original documentation identifies these Windows Security event IDs as detection opportunities.

| Event ID | Documented detection purpose |
|---|---|
| 4720 | User account created |
| 4722 | User account enabled |
| 4732 | Member added to a security-enabled local group |

These events can provide useful context when investigating account creation and subsequent changes. Event 4732 should be interpreted according to the group and membership involved rather than treated as proof of malicious activity by itself.

### SOC correlation opportunity

Investigate cases in which PowerShell execution, suspicious executable activity, outbound beaconing, and unexpected account creation occur close together on the same endpoint.

## Phase 15 — Sensitive File Discovery

![Sensitive File Discovery](assets/15_clients_csv_artifact.png)

<figure>
  <figcaption>Figure 14 — Screenshot documenting discovery of the clients.csv artifact.</figcaption>
</figure>

The original investigation reports discovery of the following file path:

```text
C:\Users\<User>\Desktop\Files\clients.csv
```

### Why the artifact matters

The filename suggests a potentially business-related dataset. The original case study treats the discovery as a relevant collection-related indicator.

The filename alone does not establish the contents, sensitivity, or successful exfiltration of the file. Those conclusions would require additional evidence.

### ATT&CK mapping

The original documentation associates the discovery activity with **T1083 — File and Directory Discovery**.

### Discovery workflow

```text
Encrypted command
        |
        v
Filesystem enumeration
        |
        v
clients.csv discovered
        |
        v
Response returned
        |
        v
File path recovered
```

This evidence indicates that the investigation progressed beyond endpoint identification into filesystem discovery.

## Phase 16 — Sensitive File Access

![Answer Validation](assets/16_answer_validation.png)

<figure>
  <figcaption>Figure 15 — Original screenshot associated with sensitive file response and challenge validation.</figcaption>
</figure>

The original documentation reports that decrypted responses contained information associated with the discovered CSV file.

The specific sensitive artifact and final challenge answer remain redacted.

```text
Recovered artifact:
[REDACTED]
```

### Interpretation

The documented evidence supports filesystem discovery and a subsequent response containing file-related information. It should not be expanded into a claim of confirmed data exfiltration unless the underlying evidence establishes that the data was transmitted out of the environment.

## Phase 17 — Indicators of Compromise

The following indicators are retained from the original case study.

### Network indicators

| Indicator | Original interpretation |
|---|---|
| `10.0.2.37` | Havoc Teamserver / HTTP infrastructure |
| `10.0.2.38` | Compromised Windows workstation |
| TCP `1337` | Executable-delivery service |
| HTTP POST | Encrypted beacon communication |
| AES-CTR | Encryption associated with the analyzed C2 traffic |

### Host indicators

| Indicator | Original interpretation |
|---|---|
| `install.ps1` | PowerShell downloader |
| `notepad.exe` | Masquerading Havoc payload |
| `demon.x64.exe` | Embedded malware-related identifier |
| Downloads directory | Documented malware staging location |
| `clients.csv` | Business-related file discovered during filesystem investigation |

### Confidence and limitations

The original documentation reports high confidence in its major findings. This table preserves the categories but does not treat every indicator as universally malicious.

| Finding | Evidence described in the source |
|---|---|
| PowerShell downloader | Recovered HTTP stream |
| Havoc Demon attribution | Static strings and threat-intelligence correlation |
| Encrypted beacon traffic | Repeated HTTP POST requests and protocol analysis |
| AES session recovery | Registration packet analysis |
| Persistence account | Decrypted response and persistence artifact |
| Sensitive file discovery | Decrypted filesystem-related response |

The IP addresses, port, filenames, and traffic characteristics are lab-specific indicators. In production environments, they should be correlated with additional telemetry before blocking or assigning malicious status.

## Incident Timeline Reconstruction

The following timeline summarizes the sequence documented in the original investigation.

```text
EVIDENCE ACQUISITION
        |
        v
HTTP CONVERSATION ISOLATION
        |
        v
PowerShell downloader recovered
        |
        v
Executable downloaded
        |
        v
Havoc Demon attribution
        |
        v
DEMON_INIT registration identified
        |
        v
AES session analysis
        |
        v
Encrypted metadata decrypted
        |
        v
Windows identity and network discovery
        |
        v
Local account creation identified
        |
        v
clients.csv discovered
        |
        v
IOC correlation and detection planning
```

### Incident progression

| Stage | Recovered evidence |
|---|---|
| Initial delivery | HTTP retrieval of `install.ps1` |
| Payload transfer | HTTP retrieval of `notepad.exe` |
| Malware identification | Static strings and threat-intelligence correlation |
| Command and control | Havoc registration and encrypted beacon traffic |
| Cryptographic analysis | AES-CTR session material and protocol offsets |
| Discovery | Windows identity and network configuration artifacts |
| Persistence | Local account creation |
| Filesystem investigation | Discovery of `clients.csv` |
| Defensive analysis | IOC extraction, ATT&CK mapping, and detection opportunities |

This timeline is a reconstruction of the documented sequence. It is not a substitute for a timestamped event chronology derived from the original packet capture.

## Evidence Correlation Matrix

| Evidence source | Documented finding |
|---|---|
| HTTP stream | PowerShell downloader recovered |
| HTTP objects | Executable extracted |
| Static strings | Havoc Demon attribution supported |
| Threat intelligence | Malware-family correlation |
| Registration packet | Protocol fields and cryptographic material identified |
| CyberChef workflow | Encrypted metadata decrypted |
| Decrypted beacon traffic | Windows reconnaissance recovered |
| Decrypted responses | Persistence and filesystem discovery documented |

The strongest conclusions arise from correlating multiple sources rather than relying on an isolated filename, network request, or string.

## MITRE ATT&CK Mapping

The following mappings are those documented in the original investigation. They represent the original analyst's behavioral classification, not an independently verified mapping of every event in the packet capture.

| Technique | Technique name | Documented evidence |
|---|---|---|
| [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | PowerShell | Recovered PowerShell downloader |
| [T1105](https://attack.mitre.org/techniques/T1105/) | Ingress Tool Transfer | HTTP executable delivery |
| [T1036](https://attack.mitre.org/techniques/T1036/) | Masquerading | `notepad.exe` used as the payload filename |
| [T1016](https://attack.mitre.org/techniques/T1016/) | System Network Configuration Discovery | Network configuration and IPv6 enumeration |
| [T1033](https://attack.mitre.org/techniques/T1033/) | System Owner/User Discovery | Username-related investigation |
| [T1083](https://attack.mitre.org/techniques/T1083/) | File and Directory Discovery | `clients.csv` discovery |
| [T1136](https://attack.mitre.org/techniques/T1136/) | Create Account | Local Windows account creation |
| [T1071.001](https://attack.mitre.org/techniques/T1071/001/) | Web Protocols | HTTP-based command-and-control communication |
| [T1573](https://attack.mitre.org/techniques/T1573/) | Encrypted Channel | AES-CTR encrypted communications |

### Mapping considerations

- T1059.001 is associated with the recovered PowerShell activity.
- T1105 is associated with the documented transfer of the executable.
- T1036 reflects the original analysis of the executable's deceptive filename.
- T1016, T1033, and T1083 relate to the documented endpoint-discovery activities.
- T1136 relates to the reported local account creation.
- T1071.001 and T1573 describe the documented HTTP and encrypted communication characteristics.

Technique mapping should be based on observed behavior. Encryption alone does not prove malicious command execution, and an indicator such as an executable filename is more persuasive when correlated with its path, contents, process activity, and network behavior.

## Detection Engineering

The original investigation turns the recovered evidence into detection opportunities for endpoint monitoring, network security monitoring, SIEM correlation, and threat hunting.

The rules and queries below are presented as investigation concepts or as the original documented examples. They are not represented as tested production detections.

### Detection strategy

| Security layer | Detection opportunity |
|---|---|
| Endpoint | Suspicious PowerShell execution and downloader behavior |
| Process monitoring | Executable launched from a user-controlled Downloads directory |
| Network monitoring | HTTP executable delivery |
| Network monitoring | Repeated HTTP POST beacon patterns |
| Identity monitoring | Unexpected local account creation |
| Filesystem monitoring | Unusual discovery of sensitive user files |

### PowerShell downloader detection

Investigate PowerShell activity that correlates with:

1. An outbound HTTP request.
2. Retrieval of an executable.
3. Creation of a local file.
4. Execution of the downloaded file.
5. Subsequent communication with a suspicious server.

Useful telemetry identified in the original documentation includes Microsoft Defender, Sysmon, Windows Security logs, Sentinel, and Splunk.

A single PowerShell event is not enough to establish malicious behavior. Correlation across process, network, file, and identity telemetry improves the quality of the investigation.

### Masquerading executable detection

The original detection concept focuses on `notepad.exe` executing outside its expected Windows directory.

```text
Executable name:
notepad.exe

AND

Executable path:
not the expected Windows system location

AND

Correlated suspicious network activity
```

The original documentation specifically references:

```text
C:\Windows\System32\
```

This is a hunting concept rather than a complete Sigma rule. Production implementations should account for legitimate installations, alternate Windows locations, process metadata, file signatures, and the actual executable path.

### Sysmon coverage

The original case study identifies the following Sysmon event IDs for investigation.

| Event ID | Documented use |
|---|---|
| 1 | Process creation |
| 3 | Network connection |
| 7 | Image loaded |
| 11 | File created |
| 13 | Registry value modification |
| 22 | DNS query |

These event types provide different parts of the investigative timeline. Their availability depends on the deployed Sysmon configuration, filtering rules, and data collection pipeline.

### Process and network correlation

```text
PowerShell process
        |
        v
HTTP download
        |
        v
File creation
        |
        v
Executable launch
        |
        v
Outbound beacon activity
        |
        v
Account creation
```

The sequence is a correlation hypothesis derived from the original investigation. A production detection should use timestamps, process identifiers, host identity, and destination details to associate events reliably.

### Network IDS detection concepts

The original documentation proposes Suricata-style detection ideas for:

- HTTP responses containing executable content.
- Binary transfers over unexpected internal HTTP services.
- Repeated POST requests to a fixed destination.
- Small binary payloads and repeated communication intervals.

The original lab identifies TCP port `1337` as a relevant delivery service.

Port numbers and HTTP methods are not sufficient to determine maliciousness. Network detections should account for known internal services, content characteristics, endpoint context, and other corroborating indicators.

### Beacon behavior profile

```text
HTTP POST request
        |
        v
Binary payload
        |
        v
Encrypted communication
        |
        v
HTTP response
        |
        v
Next beacon or task
```

This is the documented behavioral pattern. It is not a standalone signature for Havoc, since legitimate applications may also use HTTP POST and encrypted binary communication.

### Splunk hunting examples

The following query examples are preserved from the original documentation.

#### Hunt 1 — PowerShell execution

```spl
index=windows EventCode=4688 powershell.exe
```

**Purpose:** Identify process-creation events associated with PowerShell, where the relevant event data is available.

The original query is a starting point. Actual field names and matching syntax depend on the Windows data source and Splunk field extraction.

#### Hunt 2 — Downloads directory execution

```text
process_path="*\\Downloads\\*.exe"
```

**Purpose:** Identify executable launches from Downloads directories when the endpoint telemetry supports the relevant path field.

This is a filter concept rather than a complete, independently validated SPL search.

#### Hunt 3 — Local account creation

```text
EventCode=4720
```

**Purpose:** Investigate Windows account-creation events and correlate them with suspicious endpoint and network activity.

#### Hunt 4 — Correlation hunt

```text
PowerShell execution
        |
        v
File download
        |
        v
Executable launch
        |
        v
HTTP beacon
        |
        v
Account creation
```

The purpose is to identify a chain of related activity on the same endpoint rather than alerting on each event without context.

### Sigma detection concepts

The original documentation identifies two main Sigma-oriented use cases:

- Suspicious PowerShell downloader behavior.
- Masquerading executable execution.

The intended logic is to correlate PowerShell activity, executable retrieval, file creation, execution from a user-controlled directory, and suspicious outbound traffic.

No complete Sigma YAML rule was supplied in the original document. A new rule is therefore not fabricated here.

## Threat Hunting Playbook

The following hunting scenarios preserve the investigative themes documented in the original case study.

### Hunt 1 — PowerShell downloader activity

**Objective:** Identify endpoints where PowerShell execution is followed by binary retrieval and executable launch.

| Telemetry | Investigative question |
|---|---|
| Process creation | Which process launched PowerShell? |
| Network events | Did the endpoint make a related HTTP request? |
| File creation | Was an executable written locally? |
| Process execution | Was the downloaded executable launched? |

**ATT&CK context:** T1059.001, T1105, and T1036.

### Hunt 2 — Internal HTTP malware delivery

**Objective:** Identify internal services distributing unexpected executable files.

Investigate:

- HTTP GET requests returning executable content.
- Internal services using unexpected ports, including the lab's documented TCP port `1337`.
- Executables written to user-controlled directories.
- Subsequent process execution.

The original documentation describes a Python HTTP server in the lab infrastructure. That observation should be validated against the available process and network telemetry in a real investigation.

### Hunt 3 — Havoc beacon detection

**Objective:** Identify suspicious repeated HTTP POST traffic.

| Behavior | Investigative value |
|---|---|
| Repeated POST requests | Potential beaconing |
| Fixed destination | Infrastructure correlation |
| Binary payloads | Requires content and protocol analysis |
| Repeated timing | Potential beacon-interval pattern |

The original investigation uses protocol analysis and AES-CTR decryption to distinguish relevant messages from other binary traffic.

### Hunt 4 — Persistence detection

**Objective:** Identify local account creation that follows suspicious downloader or beacon activity.

| Sequence | Telemetry |
|---|---|
| PowerShell execution | Windows process-creation telemetry |
| Network activity | Sysmon Event ID 3, when configured |
| Executable launch | Sysmon Event ID 1 |
| User creation | Windows Security Event ID 4720 |
| Continued beaconing | Network telemetry |

Correlate the events by endpoint and time window, and investigate whether the account creation was authorized.

### Hunt 5 — Sensitive file discovery

**Objective:** Investigate suspicious processes searching user directories for potentially valuable business data.

The original documentation discusses CSV, XLSX, PDF, and Desktop files as potential hunting targets.

| File category | Potential investigation context |
|---|---|
| CSV | Business records and customer datasets |
| XLSX | Financial or business information |
| PDF | Reports and documents |
| Desktop files | User-accessible documents |

File types alone are not indicators of compromise. Detection should focus on the process, access pattern, context, and any associated network or command-and-control activity.

### Hunt 6 — IOC correlation

**Objective:** Combine network and host indicators to establish whether a suspicious activity chain is present.

The documented investigation provides the following starting points:

- `10.0.2.37`
- `10.0.2.38`
- `install.ps1`
- `notepad.exe`
- `demon.x64.exe`
- `clients.csv`
- Repeated HTTP POST traffic
- AES-CTR communication

These indicators should be enriched with process, file, timestamp, and network context before being used in production detection logic.

## Detection Coverage Matrix

| Capability | Documented coverage |
|---|---|
| Network forensics | PCAP and HTTP stream analysis |
| Malware triage | Static strings and threat-intelligence correlation |
| Protocol analysis | Havoc registration and header investigation |
| Cryptographic analysis | AES-CTR session recovery and traffic decryption |
| IOC extraction | Network and host artifact correlation |
| Endpoint detection | PowerShell, file creation, and process execution concepts |
| Identity detection | Local account creation |
| Threat hunting | Cross-source incident timeline reconstruction |
| ATT&CK mapping | Classification of documented behaviors |

## Security Findings

The original investigation supports the following principal findings.

<div class="key-finding">

  <div class="key-finding-title">Finding 01 — HTTP-Based Payload Delivery</div>

  The packet capture contains a documented request for `install.ps1`,
  followed by retrieval of `notepad.exe`. The sequence provides evidence of
  the delivery chain examined in the original investigation.

</div>

<div class="key-finding">

  <div class="key-finding-title">Finding 02 — Havoc Demon Attribution</div>

  Static string analysis identifies `demon.x64.exe`, and the original
  documentation reports corroborating threat-intelligence findings
  associated with Havoc Demon.

</div>

<div class="key-finding">

  <div class="key-finding-title">Finding 03 — Encrypted Command and Control</div>

  The original investigation identifies repeated HTTP POST traffic and
  analyzes the Havoc registration packet to recover the documented
  cryptographic material required for AES-CTR decryption.

</div>

<div class="key-finding">

  <div class="key-finding-title">Finding 04 — Windows Reconnaissance</div>

  Decrypted traffic is reported to contain endpoint identity and network
  configuration artifacts, including username-related information, SID
  evidence, and IPv6-related information.

</div>

<div class="key-finding">

  <div class="key-finding-title">Finding 05 — Local Account Creation</div>

  The original investigation reports a new local Windows account as a
  persistence-related artifact. The associated username and password remain
  redacted.

</div>

<div class="key-finding">

  <div class="key-finding-title">Finding 06 — Filesystem Discovery</div>

  The original investigation documents discovery of
  `C:\Users\<User>\Desktop\Files\clients.csv`. This supports a finding of
  filesystem discovery; it does not, by itself, establish successful
  exfiltration.

</div>

## Defensive Recommendations

The recommendations below are derived from the specific behaviors documented in the case study.

| Finding | Risk or concern | Recommended control |
|---|---|---|
| PowerShell downloader | Script-based payload retrieval and execution | Enable appropriate PowerShell logging and correlate script activity with network and process events |
| Executable delivered over HTTP | Unexpected binary transfer | Monitor internal HTTP services and correlate transferred files with endpoint execution |
| Masquerading filename | Executable identity may be misleading | Monitor executable paths, file metadata, signatures, and process behavior |
| Encrypted beaconing | Limited visibility into payload contents | Correlate network behavior with endpoint telemetry and investigate suspicious recurring connections |
| Local account creation | Potential unauthorized access | Alert on unexpected account creation and changes to local group membership |
| Network configuration discovery | Possible post-compromise reconnaissance | Correlate discovery behavior with suspicious process and network activity |
| Sensitive file discovery | Potential targeting of business information | Monitor unusual filesystem access patterns and investigate associated process behavior |

### Suggested defensive priorities

1. **PowerShell visibility:** Enable appropriate script logging and collect relevant endpoint telemetry.
2. **Process and file correlation:** Investigate suspicious executables created in user-controlled locations and subsequently executed.
3. **Network monitoring:** Alert on suspicious executable delivery and recurring communication patterns.
4. **Identity monitoring:** Investigate unexpected account creation and privilege-related changes.
5. **Evidence correlation:** Combine network, process, file, and identity telemetry into a single incident timeline.
6. **Threat hunting:** Reuse the documented IOCs as starting points while validating them against the actual environment.

The recommendations are tied to the documented incident. They are not intended to replace environment-specific tuning or incident-response procedures.

## Lessons Learned

### 1. Network evidence can reveal a complete delivery sequence

HTTP stream reconstruction provides a way to examine the downloader and the executable transfer without executing the payload.

### 2. Static analysis supports safer malware triage

The original investigation uses strings and threat-intelligence correlation to support attribution while avoiding unnecessary execution of the suspicious binary.

### 3. Protocol framing matters during decryption

The documented request and response headers have different lengths. Correctly identifying the encrypted payload boundaries is essential to the original AES-CTR workflow.

### 4. Decryption makes host activity interpretable

The original investigation uses decrypted metadata and responses to reconstruct endpoint identity, network discovery, persistence, and filesystem activity.

### 5. Indicators gain value through correlation

An HTTP request, executable filename, or local account event may have legitimate explanations in isolation. Their significance increases when they align with other documented events in the same incident.

### 6. Forensic findings should inform detection engineering

The recovered behaviors provide starting points for endpoint monitoring, network detection, identity alerts, and SIEM correlation.

### 7. Findings must be stated at the level supported by evidence

Discovering a sensitive filename does not automatically prove that data was exfiltrated. A sound incident report separates observed activity from inferred impact.

## Skills Demonstrated

| Domain | Skills represented in the investigation |
|---|---|
| Network forensics | PCAP analysis, TCP conversations, HTTP stream reconstruction |
| Malware analysis | Static strings, executable triage, threat-intelligence correlation |
| DFIR | Evidence collection, correlation, incident timeline reconstruction |
| Command and control | Havoc Demon attribution and registration packet analysis |
| Cryptography | AES-CTR analysis, key and IV handling, encrypted traffic decryption |
| Windows investigation | Identity artifacts, network configuration, account creation, filesystem discovery |
| Threat hunting | IOC correlation and behavioral investigation |
| Detection engineering | Sigma concepts, Sysmon telemetry, Splunk hunting, Suricata concepts |
| MITRE ATT&CK | Documented behavior mapping |
| Technical reporting | Evidence-based findings, redaction, defensive recommendations |

## Learning Outcomes

The investigation demonstrates how network telemetry can be used to reconstruct a malware incident from delivery through post-compromise activity.

The principal learning outcomes are:

- Use Wireshark to isolate conversations and reconstruct HTTP streams.
- Extract suspicious objects for static examination.
- Correlate executable strings with threat-intelligence findings.
- Identify the documented Havoc registration packet and its protocol fields.
- Understand the role of AES-CTR parameters and payload offsets in the documented decryption workflow.
- Interpret decrypted endpoint metadata and command responses.
- Reconstruct Windows identity, network, persistence, and filesystem artifacts.
- Convert forensic observations into actionable detection and threat-hunting hypotheses.

## References

The original documentation identifies the following resources. The entries are retained without inventing specific article titles or source URLs.

| Resource | Purpose |
|---|---|
| TryHackMe — Mayhem | Investigation scenario |
| Wireshark Documentation | Packet capture and network protocol analysis |
| CyberChef Documentation | Data transformation and AES-CTR workflow |
| MITRE ATT&CK Framework | Behavioral technique classification |
| Havoc C2 Research | Understanding the documented command-and-control protocol |

The MITRE ATT&CK technique links in the mapping section point to the corresponding official technique pages.

The original documentation does not provide specific URLs for the TryHackMe room, Wireshark documentation, CyberChef documentation, or Havoc research. No replacement links are fabricated.

## Responsible Use

> This documentation was created for authorized cybersecurity training and CTF environments. Network forensics, malware analysis, cryptographic investigation, and detection techniques should only be applied to systems and evidence that you are authorized to examine. Handle recovered credentials, cryptographic material, and sensitive artifacts according to applicable security and disclosure requirements.

The original challenge flags, passwords, session keys, initialization vectors, SIDs, IPv6 values, and persistence credentials remain redacted.

## Conclusion

The Mayhem investigation demonstrates an evidence-driven approach to reconstructing a simulated Havoc command-and-control compromise.

Starting with `traffic.pcapng`, the documented workflow isolates the relevant network conversations, recovers the PowerShell downloader and executable, correlates static malware evidence, investigates the Havoc registration protocol, and decrypts selected traffic using the documented AES-CTR methodology.

The resulting artifacts support reconstruction of Windows identity and network discovery, local account creation, and filesystem discovery. The investigation then translates those findings into IOC correlation, ATT&CK mapping, detection engineering, and threat-hunting opportunities.

The principal lesson is that effective DFIR depends on correlating network, protocol, and endpoint evidence while distinguishing verified observations from assumptions about attacker intent or impact.
