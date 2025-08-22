# Brute Force Attempt Detection with Microsoft Sentinel

##  Objective
Develop and implement a Microsoft Sentinel alert rule to detect brute force login attempts on Azure virtual machines, investigate the incident in accordance with the **NIST 800-61 Incident Response Lifecycle**, and apply security controls to prevent recurrence.

<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/3fdb240c-885a-42a9-8c44-2146a490755f" 
    height="365" 
    width="701" 
    alt="SS_SecOps_BF_Image"
  />
</p>

---

##  Process & Implementation

### 1. Alert Rule Creation
- Configured a Sentinel **Scheduled Query Rule** to trigger when the same remote IP address fails to log in to the same Azure VM **10 or more times within 5 hours**.
- Utilized the `DeviceLogonEvents` table from Microsoft Defender for Endpoint logs, ingested into the **Log Analytics Workspace**.

**Detection Query:**
```kusto
DeviceLogonEvents
| where ActionType == "LogonFailed" and TimeGenerated > ago(5h)
| summarize EventCount = count() by RemoteIP, ActionType, DeviceName
| where EventCount >= 30
| order by EventCount
```

---

### 2. Detection & Analysis
- Identified **10 virtual machines** targeted by brute force attempts from **10 distinct public IP addresses**.

**TOP IP offenders:**
1. `27.123.9.202` – 203 failed attempts
2. `101.228.95.29` – 100 failed attempts
3. `101.88.29.212` – 65 failed attempts

**Verification for Successful Logins:**

**Detection Query:**
```kusto
DeviceLogonEvents
| where RemoteIP in ("27.123.9.202","101.228.95.29","101.88.29.212")
| where ActionType != "LogonFailed"
```
**Result:** No successful logins detected from identified brute force IP addresses.

<p align="center">
  <img 
    src="https://github.com/user-attachments/assets/74a89a4d-0cf8-435e-91ab-0959f6f3d05b" 
    height="365" 
    width="701" 
    alt="SS_SecOps_BF_Attempts"
  />
</p>

---

### 3. Containment & Recovery
**Actions Taken:**
- Isolated all affected devices in **Microsoft Defender for Endpoint (MDE)**.
- Executed anti-malware scans on all devices using MDE.
- Updated **Network Security Groups (NSGs)** to allow inbound access only from the administrator’s local machine.

---

### 4. Post-Incident Measures
- Proposed a **company-wide Azure Policy** to enforce NSG restrictions, preventing public RDP access on all VMs.
- Documented investigation and response process for future use.

---

### Outcome
- **No successful compromise detected.**
- Strengthened security posture through network restrictions and policy recommendations.
- Incident closed after confirming system integrity.

---

###  Skills & Tools Used
- **Microsoft Sentinel**
- **Microsoft Defender for Endpoint (MDE)**
- **Azure Network Security Groups (NSG)**
- **Log Analytics & KQL**
- **Incident Response – NIST 800-61**
- **Brute Force Detection & Mitigation**


