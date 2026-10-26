# NetSentry AI — Limitations & Future Work

## 1. Candid Technical Assessment

In academic machine learning and cybersecurity research, demonstrating intellectual honesty by clearly recognizing the boundaries, physical bottlenecks, and adversarial failure modes of a system is as important as presenting its strengths.

NetSentry AI provides a high-performance, leakage-free flow analysis platform; however, real-world deployment in Tier-1 telecommunications networks or high-throughput enterprise perimeters introduces fundamental hardware, cryptographic, and algorithmic challenges.

---

## 2. Intrinsic Limitations

### 2.1. Software vs Line-Rate Hardware Throughput Bottlenecks
- **The Physical Reality**: A saturated 10 Gbps Ethernet link transmits up to **14.88 million packets per second** (at minimum 64-byte frame size) or **833,000 packets per second** (at 1,500-byte MTU).
- **Python / User-Space Overhead**: In pure user-space Python, context switching, OS socket interrupts, and memory copying restrict raw packet ingestion to approximately $50,000 - 100,000\text{ packets/sec}$ per core.
- **Architectural Boundary**: NetSentry AI is designed as a **Network Detection and Response (NDR)** / **SIEM Analytic Tier** that consumes sampled NetFlow/IPFIX records or SPAN-port buffers, rather than an in-line bump-in-the-wire hardware packet filter.

### 2.2. Payload Blindness & Single-Packet Exploits
- **The Trade-Off**: Operating exclusively on Layer 3/4 flow metadata preserves privacy and operates across TLS 1.3 encrypted streams.
- **Vulnerability**: Single-packet application exploits that mimic normal HTTP flows (e.g. Log4Shell JNDI injection in a single `User-Agent` header, SQL injection in a small POST request) do not alter flow duration, byte rate, or packet counts. Flow-only ML models are inherently blind to these exploits unless combined with web application firewall (WAF) reverse proxies.

### 2.3. Flow Export Latency & Preventive Blocking
- **Flow Expiration Window**: Network taps aggregate packets into a flow record only after a TCP connection completes (`FIN` / `RST`) or when an active flow timeout (typically 15 to 30 seconds) expires.
- **Operational Implication**: Flow-based NIDS are primarily **detective** rather than **preventive**. By the time a flow record is exported, parsed, and scored by NetSentry AI, the initial malicious payload has already traversed the network wire to the target host. Mitigation relies on dynamic firewall/ACL blacklisting of the attacker's IP for subsequent connections.

### 2.4. Adversarial Machine Learning & Evasion Attacks
Machine learning models are vulnerable to targeted evasion by sophisticated threat actors:
1. **Flow Padding**: An attacker conducting automated data exfiltration can deliberately pad transmissions with random delays or split files into small chunks matching benign web browsing packet distributions.
2. **Rate Throttling (Low-and-Slow Attacks)**: Scanning tools (e.g. `nmap -T0` / `T1`) randomize port intervals over hours, remaining below flow-rate anomaly thresholds.
3. **Poisoning**: Attackers with persistent footholds can gradually inject anomalous benign traffic to shift baseline medians, normalizing malicious behaviors over time.

---

## 3. Future Work & Engineering Roadmap

To advance NetSentry AI into a commercial-grade, multi-gigabit intrusion defense platform, the following engineering enhancements are planned:

### 3.1. eBPF / XDP Kernel-Bypass Ingestion
- Implement **eXpress Data Path (XDP)** inside the Linux kernel to aggregate 5-tuple flows directly in network driver ring buffers before socket buffer allocation.
- Compile lightweight decision trees (via TreeLite or Cython) directly into **eBPF bytecode** executed within kernel space, achieving line-rate filtering at $>10\text{ Gbps}$ with zero user-space context switching.

### 3.2. P4 Programmable Data Plane Hardware Offloading
- Target **P4-programmable switches** (e.g. Intel Tofino ASIC) to extract flow statistics and execute linear decision boundaries (Logistic Regression / Linear SVM) in hardware pipeline stages at multi-terabit line rates.

### 3.3. Self-Supervised Domain Adaptation (UDA)
- Incorporate contrastive self-supervised pre-training (e.g. SimCLR adapted for flow tabular data) to learn domain-invariant representations across diverse enterprise networks, reducing the $35\%+$ Macro-F1 drop observed during cross-dataset transfers.

### 3.4. Hybrid Multimodal Fusion (Flow + Encrypted SNI / TLS Fingerprinting)
- Augment Layer 3/4 flow features with unencrypted Layer 7 metadata: **JA3/JA4 TLS Client Fingerprints**, Server Name Indication (SNI) hashes, and certificate anomaly metrics to detect C2 beacons without decrypting payloads.
