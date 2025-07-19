# Study Guide for Exam SC-200: Microsoft Security Operations Analyst

Updated 2025-July-19

## Manage a security operations environment (20–25%)
- **Configure settings in Microsoft Defender XDR**

| Area | Notes |
|---|---|
| [Configure alert notifications](https://learn.microsoft.com/en-us/defender-xdr/configure-email-notifications) | xxxx | 
| [Configure vulnerability email notifications in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/configure-vulnerability-email-notifications) | xxxx |
| [Configure Defender for Endpoint advanced features](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features) <br/> &bull; Live Response <br/> &bull; Custom Network Indicators <br/> &bull; Tamper Protection| System > Settings > Endpoints > Advanced  |

  - Configure endpoint rule (and exclusion) settings
     - System > Settings > Endpoints > Rules 

| Area | Notes |
|---|---|
| xxxx | xxxx |
  
  - Manage automated investigation and response capabilities in Microsoft Defender XDR
  - [Configure automatic attack disruption in Microsoft Defender XDR
](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption) | System > Settings > Endpoints > Device groups under Permissions. |

- [Create an endpoint security policy](https://learn.microsoft.com/en-us/defender-endpoint/manage-security-policies#create-an-endpoint-security-policy)




- **Manage assets and environments**
  - Configure and manage device groups, permissions, and automation levels in Microsoft Defender for Endpoint
  - Identify unmanaged devices in Microsoft Defender for Endpoint
  - Discover unprotected resources by using Defender for Cloud
  - Identify and remediate devices at risk by using Microsoft Defender Vulnerability Management
  - Mitigate risk by using Exposure Management in Microsoft Defender XDR


| Term | Description |
|---|---|
| xxxx | xxxx | 


## Design and configure a Microsoft Sentinel workspace

- **Plan a Microsoft Sentinel workspace**
  - Configure Microsoft Sentinel roles
  - Specify Azure RBAC roles for Microsoft Sentinel configuration
  - Design and configure Microsoft Sentinel data storage, including log types and log retention

| Term | Description |
|---|---|
| xxxx | xxxx | 

- **Ingest data sources in Microsoft Sentinel**
  - Identify data sources to be ingested for Microsoft Sentinel
  - Implement and use Content hub solutions
  - Configure and use Microsoft connectors for Azure resources, including Azure Policy and diagnostic settings
  - Plan and configure Syslog and Common Event Format (CEF) event collections
  - Plan and configure collection of Windows Security events by using data collection rules, including Windows Event Forwarding (WEF)
  - Create custom log tables in the workspace to store ingested data
  - Monitor and optimize data ingestion

| Term | Description |
|---|---|
| xxxx | xxxx | 

## Configure protections and detections (15–20%)

- **Configure protections in Microsoft Defender security technologies**
  - Configure policies for Microsoft Defender for Cloud Apps
  - Configure policies for Microsoft Defender for Office 365
  - Configure security policies for Microsoft Defender for Endpoints, including attack surface reduction (ASR) rules
  - Configure cloud workload protections in Microsoft Defender for Cloud

| Term | Description |
|---|---|
| xxxx | xxxx | 


- **Configure detections in Microsoft Defender XDR**
  - Configure and manage custom detection rules
  - Manage alerts, including tuning, suppression, and correlation
  - Configure deception rules in Microsoft Defender XDR

| Term | Description |
|---|---|
| xxxx | xxxx | 


- **Configure detections in Microsoft Sentinel**
  - Classify and analyze data by using entities
  - Configure and manage analytics rules
  - Query Microsoft Sentinel data by using ASIM parsers
  - Implement behavioral analytics

| Term | Description |
|---|---|
| xxxx | xxxx | 


## Manage incident response (25–30%)

- **Respond to alerts and incidents in the Microsoft Defender portal**
  - Investigate and remediate threats by using Microsoft Defender for Office 365
  - Investigate and remediate ransomware and business email compromise incidents identified by automatic attack disruption
  - Investigate and remediate compromised entities identified by Microsoft Purview data loss prevention (DLP) policies
  - Investigate and remediate threats identified by Microsoft Purview insider risk policies
  - Investigate and remediate alerts and incidents identified by Microsoft Defender for Cloud workload protections
  - Investigate and remediate security risks identified by Microsoft Defender for Cloud Apps
  - Investigate and remediate compromised identities that are identified by Microsoft Entra ID
  - Investigate and remediate security alerts from Microsoft Defender for Identity
  - Respond to alerts and incidents identified by Microsoft Defender for Endpoint
    - Investigate device timelines
    - Perform actions on the device, including live response and collecting investigation packages
    - Perform evidence and entity investigation

| Term | Description |
|---|---|
| [Investigations](https://learn.microsoft.com/en-us/training/modules/mitigate-incidents-microsoft-365-defender/4-investigate-incidents) | Within Defender DXR, select Investigations to see all the automated investigations triggered by alerts in this incident. The investigations will perform remediation actions or wait for analyst approval of actions. If any actions are pending for approval as part of the investigation, they'll appear in the Pending actions tab.|
| Evidence and Responses| Microsoft Defender XDR automatically investigates all the incidents' supported events and suspicious entities in the alerts, providing you with autoresponse and information about the important files, processes, services, emails, and more. This helps quickly detect and block potential threats in the incident. Each of the analyzed entities will be marked with a verdict (Malicious, Suspicious, Clean) and a remediation status. This helps you understand the remediation status of the entire incident and the next steps to further remediate.|
| Graph| The graph visualizes associated cybersecurity threats information into an incident so you can see the patterns and correlations coming in from various data points. You can view such correlation through the incident graph. The Graph tells the story of the cybersecurity attack. |
| [XDR Incident Severity - High (Red)](https://learn.microsoft.com/en-us/training/modules/mitigate-incidents-microsoft-365-defender/5-manage-investigate-alerts) | Alerts commonly seen associated with advanced persistent threats (APT). These alerts indicate a high risk because of the severity of damage they can inflict on devices. Examples include credential theft tools activities, ransomware activities not associated with any group, tampering with security sensors, or any malicious activities indicative of a human adversary.|
| XDR Incident Severity - Medium (Orange) | Alerts from endpoint detection and response post-breach behaviors that might be a part of an advanced persistent threat (APT). This includes observed behaviors typical of attack stages, anomalous registry change, execution of suspicious files, and so forth. Although some might be part of internal security testing, it requires investigation as it might also be a part of an advanced attack.|
| XDR Incident Severity - Low (Yellow) | Alerts on threats associated with prevalent malware. For example, hack-tools, nonmalware hack tools, such as running exploration commands, clearing logs, etc. often don't indicate an advanced threat targeting the organization. It could also come from an isolated security tool testing by a user in your organization.|
| XDR Incident Severity - Informational (Grey) | Alerts that might not be considered harmful to the network but can drive organizational security awareness on potential security issues.|
| Defender for Endpoint alert severity | Represents the severity of the detected behavior, the actual risk to the device, and most importantly, the potential risk to the organization.|
| Defender AV threat severity | Represents the absolute severity of the detected threat (malware) and is assigned based on the potential risk to the individual device if infected.|
| [Alert categories](https://learn.microsoft.com/en-us/training/modules/mitigate-incidents-microsoft-365-defender/5-manage-investigate-alerts) | Align closely with the attack tactics and techniques in the MITRE ATT&CK Enterprise matrix, but may also include items (like Unwanted Software) which are not part of the ATT&CK matrices.|
| Suppress alerts | There are two contexts for a suppression rule that you can choose from: <br/> &bull; Suppress alert on this device <br/> &bull; Suppress alert in my organization |





- **Investigate Microsoft 365 activities**
  - Investigate threats by using the unified audit log
  - Investigate threats by using Content Search
  - Investigate threats by using Microsoft Graph activity logs


| Term | Description |
|---|---|
| xxxx | xxxx | 


- **Respond to incidents in Microsoft Sentinel**
  - Investigate and remediate incidents in Microsoft Sentinel
  - Create and configure automation rules
  - Create and configure Microsoft Sentinel playbooks
  - Run playbooks on on-premises resources


| Term | Description |
|---|---|
| xxxx | xxxx | 


## Implement and use Microsoft Security Copilot

- **Create and use promptbooks**
- **Manage sources for Security Copilot, including plugins and files**
- **Integrate Security Copilot by implementing connectors**
- **Manage permissions and roles in Security Copilot**
- **Monitor Security Copilot capacity and cost**
- **Identify threats and risks by using Security Copilot**
- **Investigate incidents by using Security Copilot**

| Term | Description |
|---|---|
| xxxx | xxxx | 




## Manage security threats (15–20%)

- **Hunt for threats by using Microsoft Defender XDR**
  - Identify threats by using Kusto Query Language (KQL)
  - Interpret threat analytics in the Microsoft Defender portal
  - Create custom hunting queries by using KQL

| Term | Description |
|---|---|
| xxxx | xxxx | 


- **Hunt for threats by using Microsoft Sentinel**
  - Analyze attack vector coverage by using the MITRE ATT&CK matrix
  - Manage and use threat indicators
  - Create and manage hunts
  - Create and monitor hunting queries
  - Use hunting bookmarks for data investigations
  - Retrieve and manage archived log data
  - Create and manage search jobs

| Term | Description |
|---|---|
| xxxx | xxxx | 


- **Create and configure Microsoft Sentinel workbooks**
  - Activate and customize workbook templates
  - Create custom workbooks that include KQL
  - Configure visualizations

| Term | Description |
|---|---|
| xxxx | xxxx | 


---

## Supplemental Links:
[Study guide for Exam SC-200: Microsoft Security Operations Analyst](https://learn.microsoft.com/en-us/credentials/certifications/resources/study-guides/sc-200)

[Microsoft Learn SC-200 training](https://docs.microsoft.com/en-us/learn/certifications/exams/sc-200)

[YouTube - Microsoft Learn SC-200 training video series](https://www.youtube.com/playlist?list=PLahhVEj9XNTfSpvU-_iEvLJXiA0EDXkXQ)

[Microsoft Learning - Microsoft Certified Trainer (MCT) labs - SC-200 only](https://microsoftlearning.github.io/SC-200T00A-Microsoft-Security-Operations-Analyst/)

[Microsoft Learning - Microsoft Certified Trainer (MCT) labs - All exams](https://github.com/MicrosoftLearning/)

[Azure Certification Poster PDF](https://arch-center.azureedge.net/Credentials/Certification-Poster-en-us.pdf)




---
<br/> &bull;
<br/> 4 spaces = &emsp; test
<br/> Pipe symbol: &#166;
<br/> Bold: **CanNotDelete**
<br/> Bold + Italitcs ***initiatives***
<br/> [Basic writing and formatting syntax](https://docs.github.com/en/get-started/writing-on-github/getting-started-with-writing-and-formatting-on-github/basic-writing-and-formatting-syntax)
<br/> :computer:	Read the referenced URL for additional information :computer: <br/>

--- 

Notes that need to be organized
- Defender Advanced Hunting pane has access up to 30 days of logs
- When hunting Entra ID sign-in logs using KQL, the table names are different based on where you access the logs. Defender Threat Hunting table: AADSignInEventsBeta, Sentinel table: SigninLogs. 
   - The [AADSignInEventsBeta](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-aadsignineventsbeta-table) table is currently in beta and is being offered on a short-term basis to allow you to hunt through Microsoft Entra sign-in events. Customers need to have a Microsoft Entra ID P2 license to collect and view activities for this table. All sign-in schema information will eventually move to the IdentityLogonEvents table.
- Defender for Identity sensors:
  - Agentless for endpoints
  - Domain Controller sensors monitor domain domain controller traffic
  - AD FS / AD CS sensors monitor network traffic and authentication

- [Lateral Movement Paths (LMPs)](https://learn.microsoft.com/en-us/defender-for-identity/understand-lateral-movement-paths) Defender for Identity LMPs are visual guides that help you quickly understand and identify exactly how attackers can move laterally inside your network. 

- [EmailAttachmentInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-emailattachmentinfo-table) This table within the advanced hunting schema is populated by and contains information about attachments on emails processed by Microsoft Defender for Office 365 (MDO).

- [DeviceProcessEvents](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table) This table in the advanced hunting schema contains information about process creation and related events. It's populated via  Microsoft Defender for Endpoint.



Entra ID protections
 - Risky Users
 - Risky Sign-ins
 - Risky Apps
