"""Learn DCN + ML educational portal view for NetSentry AI."""
from __future__ import annotations

import streamlit as st
from ..styles import render_kpi, render_badge


def render_learn_view():
    st.markdown("## 🎓 Learn: Networking (DCN) + Machine Learning Fundamentals")
    st.caption("A beginner-to-advanced curriculum bridging Data Communication & Networking (DCN) with Machine Learning security engineering.")

    tab_flows, tab_tcp, tab_lifecycle, tab_trap, tab_glossary = st.tabs([
        "🌐 Packets vs. Flows & 5-Tuple",
        "🔌 TCP Handshakes & Attack Exploits",
        "⚙️ The ML Security Lifecycle",
        "⚠️ The Accuracy Trap",
        "📚 Interactive Cybersecurity Glossary",
    ])

    with tab_flows:
        st.markdown("### 1. From Raw Packets to Machine Learning Flows")
        st.markdown(
            """
            In high-speed computer networks, inspecting every individual packet payload with deep packet inspection (DPI) 
            is computationally prohibitive at 10 Gbps+ line rates, and is increasingly blocked by TLS/HTTPS end-to-end encryption.
            
            Instead, modern network intrusion detection systems operate on **Flows (NetFlow / IPFIX)**:
            statistical connection summaries aggregated across time.
            """
        )

        st.markdown(
            """
            <div class="netsentry-card">
                <h4>The Canonical 5-Tuple Definition</h4>
                A network flow is uniquely identified by 5 immutable network header attributes:
                <ol>
                    <li><b>Source IP Address:</b> The origin host emitting the traffic (e.g. <code>192.168.1.105</code>).</li>
                    <li><b>Destination IP Address:</b> The target receiving server (e.g. <code>10.0.0.1</code>).</li>
                    <li><b>Source Port:</b> Ephemeral port allocated on the client machine (e.g. <code>54231</code>).</li>
                    <li><b>Destination Port:</b> Well-known server service port (e.g. <code>80</code> HTTP, <code>443</code> HTTPS, <code>22</code> SSH).</li>
                    <li><b>Transport Protocol:</b> Layer 4 protocol number (<code>6</code> for TCP, <code>17</code> for UDP, <code>1</code> for ICMP).</li>
                </ol>
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.markdown("##### 📦 What Features Are Calculated from a Flow?")
        st.markdown(
            """
            | DCN Measurement | NetSentry Feature Name | Attack Signature Meaning |
            | :--- | :--- | :--- |
            | **Connection Duration** | `flow_duration_ms` | Extremely short durations (<5ms) indicate SYN/RST port scans; long durations indicate data exfiltration. |
            | **Packet Counts** | `total_fwd_packets`, `total_backward_packets` | Huge forward packets with 0 backward packets indicates an unanswered flood. |
            | **Payload Throughput** | `flow_bytes_per_second` | Spikes in bytes/sec characterize volumetric DDoS or massive database theft. |
            | **Transmission Density** | `flow_packets_per_second` | High packet rate with tiny bytes/packet represents SYN, UDP, or ICMP floods. |
            | **TCP Control Bits** | `syn_flag_count`, `rst_flag_count` | Abnormal flag ratios expose port scanning and TCP session hijacking. |
            """
        )

    with tab_tcp:
        st.markdown("### 2. TCP State Machine & How Intruders Exploit It")
        st.markdown(
            """
            The Transmission Control Protocol (TCP) provides reliable, connection-oriented data streams 
            governed by flags in the 20-byte TCP header.
            """
        )

        st.markdown(
            """
            <div class="netsentry-card">
                <h4>The Normal TCP 3-Way Handshake</h4>
                <ol>
                    <li><b>Client → Server [SYN]:</b> Client sends Synchronize flag with an Initial Sequence Number (ISN).</li>
                    <li><b>Server → Client [SYN-ACK]:</b> Server allocates connection memory buffer and acknowledges with its own ISN.</li>
                    <li><b>Client → Server [ACK]:</b> Client acknowledges. Connection state transitions to <code>ESTABLISHED</code>.</li>
                </ol>
            </div>
            """,
            unsafe_allow_html=True,
        )

        col_atk1, col_atk2 = st.columns(2)
        with col_atk1:
            st.markdown(
                """
                <div class="soc-alert soc-alert-malicious">
                    <h4>Attack 1: SYN Flood (Denial of Service)</h4>
                    <b>Mechanism:</b> The attacker transmits thousands of SYN packets from spoofed IPs and deliberately never sends the final ACK.<br><br>
                    <b>Impact:</b> The server's <i>SYN Backlog Queue</i> fills completely with half-open connections, refusing legitimate users.<br><br>
                    <b>ML Signature:</b> Huge <code>syn_flag_count</code>, near-zero <code>total_backward_packets</code>, massive <code>flow_packets_per_second</code>.
                </div>
                """,
                unsafe_allow_html=True,
            )
        with col_atk2:
            st.markdown(
                """
                <div class="soc-alert soc-alert-malicious">
                    <h4>Attack 2: TCP Half-Open Port Scan (SYN Stealth)</h4>
                    <b>Mechanism:</b> Scanner probes port 1 to 65535 by sending SYN. If server responds SYN-ACK (port open), scanner sends immediate RST.<br><br>
                    <b>Impact:</b> Uncovers open services without completing full connection, evading older application logging.<br><br>
                    <b>ML Signature:</b> Multiple flows to different <code>Destination Ports</code> with <code>flow_duration_ms < 10</code>, <code>fwd_packets = 1</code>, and <code>rst_flag_count = 1</code>.
                </div>
                """,
                unsafe_allow_html=True,
            )

    with tab_lifecycle:
        st.markdown("### 3. The 6-Stage Machine Learning Intrusion Pipeline")
        st.markdown(
            """
            ```mermaid
            graph LR
                A[1. Network Tap / PCAP] --> B[2. Flow Aggregator]
                B --> C[3. Leakage-Free Split]
                C --> D[4. Train-Only Preprocessing]
                D --> E[5. Multi-Model CV]
                E --> F[6. Threshold & Deploy]
            ```
            """
        )

        st.markdown(
            """
            1. **Raw Packet Capture:** Network hardware (SPAN port or optical TAP) captures packet bytes.
            2. **Flow Aggregator:** Aggregates packets by 5-tuple into statistical flow vectors (duration, rates, flag counts).
            3. **Leakage-Free Partitioning:** Separates data into train and test sets *before* computing scalers or imputers. Audits duplicate records and drops target labels or identifiers (Flow ID, IP, Timestamps).
            4. **Preprocessing Pipelines:** Imputes missing numbers using training medians and scales features using training standard deviations.
            5. **Cross-Validation:** 5-fold cross-validation evaluates generalization strictly on training folds. The holdout test set remains locked.
            6. **Threshold Calibration:** Decides operating threshold based on the cost of false alarms (FPR) vs missed breaches (FNR).
            """
        )

    with tab_trap:
        st.markdown("### 4. The Accuracy Trap in Cybersecurity")
        st.markdown(
            """
            Why does a model with **99.0% accuracy** often make a completely useless intrusion detector?
            
            In cybersecurity traffic, attacks are rare. Suppose our network observes **10,000 flows**:
            - 9,900 flows are normal web browsing (Benign: 99%)
            - 100 flows are ransomware beacons or DoS attacks (Malicious: 1%)
            """
        )

        st.markdown(
            """
            <div class="netsentry-card">
                <h4>Consider a "Zero-Effort" Dummy Model:</h4>
                A naive script that literally just outputs <code>return "BENIGN"</code> for every single packet:<br><br>
                - <b>Correctly predicted benign flows:</b> 9,900 / 9,900<br>
                - <b>Correctly predicted attack flows:</b> 0 / 100<br>
                - <b>Total Accuracy:</b> 9,900 / 10,000 = <b>99.0% Accuracy!</b><br>
                - <b>Attack Recall:</b> 0.0% (Every single cyber attack penetrated the network undetected)<br>
                - <b>Macro-F1:</b> 0.497 (Exposes complete detection failure!)
            </div>
            """,
            unsafe_allow_html=True,
        )

        st.info("💡 **Key Takeaway:** Never report accuracy alone in network intrusion research. Always evaluate Macro-F1, Precision-Recall AUC, and False Positive Rate.")

    with tab_glossary:
        st.markdown("### 5. Cybersecurity & ML Master Glossary")
        terms = {
            "DCN (Data Communication & Networking)": "The study and infrastructure of transmitting digital data between network nodes across communication channels.",
            "5-Tuple": "The fundamental five fields identifying a flow: Source IP, Destination IP, Source Port, Destination Port, and Protocol.",
            "PCAP": "Packet Capture file format (.pcap, .pcapng) storing raw network frames recorded by libpcap or WinPcap.",
            "Data Leakage": "When information from outside the training partition (e.g. test set statistics, session IDs, future timestamps) inappropriately influences model training, producing artificially inflated, ungeneralizable metrics.",
            "Stratified Splitting": "A partitioning method that guarantees every data split preserves the exact proportional class distribution of the original dataset.",
            "Alert Fatigue": "When security operations center (SOC) analysts are overwhelmed by thousands of daily false alarms, causing real critical attacks to be overlooked.",
            "Macro-F1": "The unweighted arithmetic mean of F1 scores across all classes. Treats rare attacks with equal weight to common benign traffic.",
            "PR-AUC": "Area Under the Precision-Recall Curve. The gold-standard evaluation metric for severely imbalanced cyber datasets.",
            "Covariate Shift": "When the input feature distribution changes between training and deployment (e.g. bandwidth increases alter byte rates), while the relationship to the label remains constant.",
            "Zero-Day Attack": "A previously unknown exploit or threat pattern for which no historical signatures or labeled training examples exist.",
            "Isolation Forest": "An unsupervised algorithm that isolates anomalies by randomly partitioning features, exploiting the fact that anomalies require fewer cuts to isolate.",
        }
        for term, definition in terms.items():
            st.markdown(f"**{term}:** {definition}")
