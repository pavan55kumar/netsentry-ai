# NetSentry AI — Dataset Provenance, Schemas & Preprocessing Report

## 1. Provenance Overview

To ensure rigorous scientific integrity, NetSentry AI trains and evaluates models exclusively on authentic, publicly available, peer-reviewed network intrusion benchmark datasets. 

Synthetic and toy datasets are strictly segregated and clearly designated.

---

## 2. Benchmark Datasets & Cryptographic Checksums

### 2.1. CIC-IDS2017 (Canadian Institute for Cybersecurity)
- **Originating Institution**: University of New Brunswick (UNB), Canadian Institute for Cybersecurity (CIC).
- **Primary Reference**: 
  > Iman Sharafaldin, Arash Habibi Lashkari, and Ali A. Ghorbani, *"Toward Generating a New Intrusion Detection Dataset and Intrusion Traffic Characterization"*, Proceedings of the 4th International Conference on Information Systems Security and Privacy (ICISSP), 2018.
- **Official Source URL**: `https://www.unb.ca/cic/datasets/ids-2017.html`
- **Mirror Distribution**: Western University OC2 Lab (`https://github.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning`).
- **Capture Environment**: Emulated production network with B-Profile background user traffic (HTTP, HTTPS, FTP, SSH, Email) and active red-team attack injection over 5 days (Monday to Friday, July 3–7, 2017).
- **Traffic Extractor**: CICFlowMeter (80+ network flow features from raw PCAPs).

#### Cryptographic Checksums & Files:
| File Path | Description | Flow Count | Feature Count | SHA-256 Checksum |
| :--- | :--- | :--- | :--- | :--- |
| `data/sample/cicids2017_authentic_sample.csv` | Full Authentic Curated Slice | 56,661 | 78 | `03BA3626A0F9BB73B90C56772893E68B0577285130891CD7D811542C17B032DD` |
| `data/sample/cicids2017_sample.csv` | Stratified Benchmark Sample | 5,000 | 78 | `7D97628E9C014586AFFEB01BE173B30DCF038B08B211F486F2A45A0224008E5C` |

#### CIC-IDS2017 Class Distribution (5,000-flow Stratified Sample):
- **BENIGN**: 2,006 (40.12%)
- **DoS** (GoldenEye, Hulk, Slowhttptest, Slowloris): 1,680 (33.60%)
- **PortScan**: 701 (14.02%)
- **BruteForce** (FTP-Patator, SSH-Patator): 244 (4.88%)
- **WebAttack** (Brute Force, XSS, SQLi): 192 (3.84%)
- **Bot** (ARES Botnet command & control): 174 (3.48%)
- **Infiltration** (Dropbox infiltration): 3 (0.06%) — *Excluded from 3-fold cross-validation due to insufficient fold support ($N<10$).*

---

### 2.2. UNSW-NB15 (Cyber Range Lab of UNSW Canberra)
- **Originating Institution**: Australian Centre for Cyber Security (ACCS), University of New South Wales (UNSW Canberra).
- **Primary Reference**:
  > Nour Moustafa and Jill Slay, *"UNSW-NB15: A comprehensive data set for network intrusion detection systems (UNSW-NB15 network data set)"*, IEEE Military Communications and Information Systems Conference (MilCIS), 2015.
- **Official Source URL**: `https://research.unsw.edu.au/projects/unsw-nb15-dataset`
- **Capture Environment**: IXIA PerfectStorm tool deployed in Cyber Range Lab to generate realistic contemporary normal activities and synthetic attack behaviors.
- **Traffic Extractor**: Argus and Bro-IDS (Zeek) combined with custom feature extraction routines (49 features).

#### Cryptographic Checksums & Files:
| File Path | Description | Flow Count | Feature Count | SHA-256 Checksum |
| :--- | :--- | :--- | :--- | :--- |
| `data/sample/unsw_nb15_authentic_sample.csv` | Full Authentic Testing Slice | 82,332 | 45 | `734FE6642EDF758F7C94D7D9149426B49D202FE8E7BF0BEF47392489C3C0A559` |
| `data/sample/unsw_nb15_sample.csv` | Stratified Benchmark Sample | 5,000 | 45 | `F6491546EE3BF77E3EA57710FA8EEBF310923BF13854E535810D84425613DC99` |

#### UNSW-NB15 Class Distribution (5,000-flow Stratified Sample):
- **Normal (Benign)**: 2,246 (44.92%)
- **Generic**: 1,146 (22.92%)
- **Exploits**: 676 (13.52%)
- **Fuzzers**: 371 (7.42%)
- **DoS**: 248 (4.96%)
- **Reconnaissance**: 213 (4.26%)
- **Analysis**: 41 (0.82%)
- **Backdoor**: 35 (0.70%)
- **Shellcode / Worms**: $< 10$ samples (filtered for cross-validation stability).

---

### 2.3. Offline PCAP Test Capture
- **File**: `data/sample/test_traffic.pcap`
- **Description**: Controlled, authorized 8-packet PCAP file containing HTTP GET, DNS queries, and TCP SYN handshakes.
- **Purpose**: Verifies bidirectional 5-tuple aggregation (`netsentry.pcap.flow_extractor`) without executing live packet sniffing on unverified networks.

---

## 3. Stratified Subset Generation Methodology

To enable fast, reproducible experimentation on standard developer laptops without CPU/RAM exhaustion, representative 5,000-flow subsets were derived using `sklearn.model_selection.StratifiedShuffleSplit`:
```python
sss = StratifiedShuffleSplit(n_splits=1, train_size=5000, random_state=42)
sample_idx, _ = next(sss.split(df, df[target_col]))
subset_df = df.iloc[sample_idx].copy().reset_index(drop=True)
```
This preserves exact natural class proportions, minority attack ratios, and intra-class feature variance, guaranteeing that models are evaluated on statistically valid distributions.

---

## 4. Preprocessing & Leakage Elimination Protocol

NetSentry AI strictly enforces three data sanitization safeguards:
1. **Target Leakage Pruning**: All columns matching regex patterns for IDs, labels, IP addresses, or timestamps (`Flow ID`, `Source IP`, `Timestamp`, `attack_cat`, `label`) are identified by `detect_target_leakage()` and dropped before model training.
2. **Infinite Value Regularization**: Due to $0$-duration flows or microscopic division in network packet rate formulas, features such as `Flow Bytes/s` occasionally equal $\pm\infty$. NetSentry converts all infinite values to `np.nan`, followed by median imputation strictly within training folds.
3. **Partition-Isolated Transformations**:
   $$\hat{\mu}_{\text{train}} = \text{median}(X_{\text{train}})$$
   $$\hat{X}_{\text{test}} = \text{transform}(X_{\text{test}}, \hat{\mu}_{\text{train}})$$
   Scalers and imputers are fitted exclusively on training folds ($X_{train}$), completely eliminating preprocessing leakage into holdout splits.
