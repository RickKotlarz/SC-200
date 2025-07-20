> Disclaimer: All information and content sourced within this repository is owned and copyrighted by Microsoft. I am not the creator or owner of this material. This repository is simply a collection of information brought together in one place for convenience and reference.

# Study Guide for Exam SC-200: Microsoft Security Operations Analyst

Updated 2025-July-19

[Essential strategies for taking the SC-200 exam: Manage a security operations environment (4 part video)](https://learn.microsoft.com/en-us/shows/exam-readiness-zone/preparing-for-sc-200-manage-a-security-operations-environment?tab=tab-description)

## Manage a security operations environment (20–25%)
- **Configure settings in Microsoft Defender XDR**

  - Configure alert and vulnerability notification rules

	| Area | Notes |
	|---|---|
	| [Configure alert notifications](https://learn.microsoft.com/en-us/defender-xdr/configure-email-notifications) | System >  Settings > Endpoints > General > Email notifications. | 
	| [Configure vulnerability email notifications in Microsoft Defender for Endpoint](https://learn.microsoft.com/en-us/defender-endpoint/configure-vulnerability-email-notifications) | xxxx |

  - Configure alert and vulnerability notification rules

	| Area | Notes |
	|---|---|
	| [Configure Defender for Endpoint advanced features](https://learn.microsoft.com/en-us/defender-endpoint/advanced-features) <br/> &bull; Live Response <br/> &bull; Custom Network Indicators <br/> &bull; Tamper Protection| System > Settings > Endpoints > Advanced  |

- Configure endpoint rule (and exclusion) settings
  - System > Settings > Endpoints > Rules 

	| Area | Notes |
	|---|---|
	| Endpoint Rules - Rules | System > Settings > Endpoints > (Rule type below) | N/A |
	| Endpoint Rules - [Alert suppresion](https://learn.microsoft.com/en-us/defender-endpoint/manage-suppression-rules) | xxxx |
	| Endpoint Rules - [Indicators](https://learn.microsoft.com/en-us/defender-endpoint/indicators-overview) | xxxx  |
	| Endpoint Rules - Isolation exclusion rules | xxxx |
	| Endpoint Rules - Process memory indicators | xxxx |
	| Endpoint Rules - Web content filtering | xxxx |
	| Endpoint Rules - Automation uploads | xxxx |
	| Endpoint Rules - Automation folder exclusions | xxxx |
	| Endpoint Rules - Asset rule management | xxxx |

  
  - Manage automated investigation and response capabilities in Microsoft Defender XDR
  
	| Area | Notes |
	|---|---|
	| xxxx | xxxx |
  
  - Configure automatic attack disruption in Microsoft Defender XDR

	| Area | Notes |
	|---|---|
	| [Configure automatic attack disruption](https://learn.microsoft.com/en-us/defender-xdr/configure-attack-disruption) | System > Settings > Endpoints > Device groups under Permissions. |
	  




- **Manage assets and environments**
  - Configure and manage device groups, permissions, and automation levels in Microsoft Defender for Endpoint
  - Identify unmanaged devices in Microsoft Defender for Endpoint
  - Discover unprotected resources by using Defender for Cloud
  - Identify and remediate devices at risk by using Microsoft Defender Vulnerability Management
  - Mitigate risk by using Exposure Management in Microsoft Defender XDR


	| Area | Notes |
	|---|---|
	| xxxx | xxxx | 


## Design and configure a Microsoft Sentinel workspace

- **Plan a Microsoft Sentinel workspace**
  - Configure Microsoft Sentinel roles
  - Specify Azure RBAC roles for Microsoft Sentinel configuration
  - Design and configure Microsoft Sentinel data storage, including log types and log retention

	| Area | Notes |
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

	| Area | Notes |
	|---|---|
	| xxxx | xxxx | 

## Configure protections and detections (15–20%)

- **Configure protections in Microsoft Defender security technologies**
  - Configure policies for Microsoft Defender for Cloud Apps
    - Configure an anomaly detection policy: 
	  - Control > Policies > Set the "Type" filter to "Anomaly detection policy"
	  - Select the policy and edit settings: Scope, Advanced configuration, Alerts, and Governance actions.
	  - You can also create a custom policy using "Create policy"
	- After policy creation you can find-tune anomaly detection for suppression or surfacing alerts as well as adjust the scope for users and groups.
  - Configure policies for Microsoft Defender for Office 365
  
    - Know the difference between a policy and a rule
	
    - Assign "Standard" or "Strict" presets security policies:
	  - Select Email & Collaboration > Policies & Rules > Threat policies > Preset Security Policies.
	- Disable "Standard Protection" or "Strict Protection"
	  - Select the recipients that "Exchange Online Protection" and "MDO" policies apply
	  - Add intneral and external senders and domains
	  - Add trusted e-mail addresses and domains
	- Order of operations when a recipeient is defined in multiple policies:
      - The Strict preset security policy
	  - The standard preset security policy
	  - MDO evaluation policies
	  - Custom policies (based on the priority of the policy, lower indicates higher priority)
	  - Built-in preset policy (includes default settings for Safe Links, Safe Attachements, Anti-Malware, Anti-Spam, Anti-Phishing) 	
  - Configure security policies for Microsoft Defender for Endpoints, including attack surface reduction (ASR) rules
    - Configured Endpoint Security policies
	  1. Select: Endpoints > Config Mgmt > Endpoint security politices > Create new Policy
	  2. Select a platform and template, then select "Create policy"
	  3. On the Basics page, enter the name and description > Next
	  4. On the Settings page, configure settings > Next
	  5. On the Assignments page, select the groups that will recieve this profile > Next
	  6. On the Review + Create page > Save.
	- Configure Attack Surface Reduction:
      1. Enable hardware-based isolation for MSFT Edge
	  2. Enable: 
	    - Attack Surface Reduction rules
		- Application control
		- Controlled folder access
		- Removable storage
	  3. Turn on network Protection
      4. Enable:
         - Web protection
         - Exploit protection
	  5. Set up your network firewall.
	  
  - Configure cloud workload protections in Microsoft Defender for Cloud
    - Resource types secured by MDC:
	  - SQL
	  - Server VMs
	  - Containers
	  - Network traffic
	  - IOT
	  - Azure App Service
	- Provides:
	  - Just-in-Time (JIT) VM access
	  - Adaptive application controls
	- Includes vulnerability assement and management
	- Remediation steps ???

	| Alert classification | Recommended response |
	|---|---|
	| High | High probability that your resource is compromised | 
	| Medium | Probably a suspicious activity might indicate that a resource is compromised | 
	| Low | Benign positive or blocked attack | 
	| Informational | Can be seen only when you drill down into a security incident, or if you use the REST API with a specefic alert ID | 

- **Configure detections in Microsoft Defender XDR**
  - Configure and manage custom detection rules
    1. Create a KQL Query within the XDR Advanced threat hunting blade
	2. Create a new rule and provide alert details
	3. Choose impacted entities
	4. Specify actions
	5. Select the rule Scope
	6. Review and turn on the rule
	
  - Manage alerts, including tuning, suppression, and correlation
  - Configure deception rules in Microsoft Defender XDR -- 5:09 min mark video 2



- **Configure detections in Microsoft Sentinel**
  - Classify and analyze data by using entities
    - Two types
	  - Asset: categorized as internal objects, protected objects, or inventoried objects
	  - Others entities: external items, not yet in your control, or IoC

    - Understand what are weak and strong identifiers used to classify entities
	
      | Entity classifiers | Meaning |
      |---|---|
      | Entity identifiers | Unique labels or attributes associated with entities within the security data and Sentinel collects and analyzes. | 
      | Entity mapping | Associating different entities within the security data to create meaningful relationships and context. | 
      | Entity pages | A clickable link that has a datasheet ful of useful information about that entity. | 
 
  - Configure analytics rules    
    1. On the "Analytics" screen, select the "Rule templates" tab
	2. Choose a template name and select the "Create rule" button
	3. The creation wizard opens with all details auto-filled.
	4. Cycle through the tabs of the wizard, customizing the logic and other rule settings to suit your needs.
  - Manage analytics rules
    1. From the Sentinel navigation mentu, select "Analytics"
	2. Find and select a rule (Scheduled or NRT) to view
	3. Select the "Insights" tab
	4. The time frame selector will appear. Select a time frame, or leave the default (last 24 hours).
	Note: The insights panel currently shows four kinds of inights:
	  1. Failed executions
	  2. Top health issues
	  3. Alert graphs
	  4. Incident classification
	
  - Query Microsoft Sentinel data by using ASIM parsers
    - Scheme or model used within SIEM solutions to reccomend, normalize, and standardize security data
    - ASIM parser types:
	  - Build in: Use in most cases where you need ASIM parsters (recommended)
	  - Workspace-deployable: Used when deploying a new parser, or for new parsers not available out-of-the-box
	- ASIM parser levels:
	  - Unifying: used when combining all sourcesnormalized to the same scheme and querying them using normalized fields
	  - Source-specefic:
    - ASIM optimizing: Optimize parsing by filtering parameters with one or more named parameters.
  - Implement behavioral analytics
    - User and Entity Behavior Analysis (UEBA)
      - Uses machine learning to establish a baseline of normal activity and then look for anomalies and potential security threats based on deviations from that baseline.
	  - Know how to enable UEBA
	  - Configure UEBA data connectors
	    - Within Sentinel navigate to the "Entity behavior configuration' page
		- Toggle on
		- Mark checkboxes next to Active Directory sources
		- Mark checkboxes next to data sources you want to enable UEBA on
		- Select "Apply"
	  - Setting up analytic rules
	  - Monitoring and investigating UEBA alerts
	  - Reviewing and tuning UEBA setting

	| Area | Notes |
	|---|---|
	| xxxx | xxxx | 


## Manage incident response (25–30%)

- **Respond to alerts and incidents in the Microsoft Defender portal**

	| Area | Notes |
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

  - Investigate and remediate threats by using Microsoft Defender for Office 365
    - Automation investigations include:
	  - Soft delete e-mail messages or clusters
	  - Block URL (time-of-click)
	  - Turn off external mail Forwarding
	  - Turn off delegation
  - Investigate and remediate ransomware and business email compromise incidents identified by automatic attack disruption
    - Three key stages
	  1. Use Defender XDR to correlate signals into a high confidence incident
	  2. Identify assets / resources controlled by an attacker
	  3. Automatically respond across the M365 Defender & security stack to contain attacks by isolating affected assets
	- Automatic attack disruption response actions:
	  - Device contain
	  - Disable user
	  - Contain user
	
  - Investigate and remediate compromised entities identified by Microsoft Purview data loss prevention (DLP) policies
  - Investigate and remediate threats identified by Microsoft Purview insider risk policies
  - Investigate and remediate alerts and incidents identified by Microsoft Defender for Cloud workload protections
    - Remediation steps:
	  - From the list, select recommediation
	  - Follow "Remediation steps"
	  - Notification pop-up appears informing you if the issue is resolved
	- Fix button:
	  - Allows you to quickly remediate a recommediation on multiple sources
	  - Select the recommediation that has a Fix action icon.
	  - From the "Unhealthy resources" tab, select the resource you want, then select "Remediate"
  - Investigate and remediate security risks identified by Microsoft Defender for Cloud Apps
  - Investigate and remediate compromised identities that are identified by Microsoft Entra ID
    - Two risk types
	  - User risks: Liklihood that a user idenity may be compromised
	  - Sign-in risks: Liklihood that a specefic authentication attempt is not performed by a legitimate user.
	- Entra ID 3-part Process
	  1. - Detection involves identifying suspicious activities and potential threats using ML algos
	  2. - Investigation involves reviewing detailed reports on risky users, sign-ins, and risk detections
	  3. - Remediation: taking action to mitigate identified risks such as enforcing MFA
	       - Workflow: Self remediation - 
		   - Workflow: Administrator remediation - 
  - Investigate and remediate security alerts from Microsoft Defender for Identity
    - MDI alerts are broken into 4-phases of alerts typically seen in the cyberattack kill chain
	  1. Reconnaissance
	     - SPN recon (LDAP)
		 - Account enum
		 - User group enum
		 - User / IP enum
		 - Host / server name enum
	  2. Compromised credentials
	     - Brute force attempts
		 - Suspicious VPN connection
		 - Honey Token account suspicious activity
	  3. Lateral movement
	     - Pass-the-ticket
		 - Pass-the-hash
		 - Overpass-the-hash
	  4. Domain dominance
	     - NTLM relay (Exchange) attack
		 - Golden ticket attack
		 - DCShadow, DCSync
		 - Data exfiltration
		 - Remote code execution on DC
		 - Skeleton Key
		 - Service creation on DC
		 - Suspicous group modifications
  - Respond to alerts and incidents identified by Microsoft Defender for Endpoint
    - Investigate device timelines
    - Perform actions on the device, including live response and collecting investigation packages
    - Perform evidence and entity investigation

- **Investigate Microsoft 365 activities**
  - Investigate threats by using the unified audit log
    - Audit (standard): Enabled by default
	- Audit (premium) // know why would you use one over the other...
	
  - Investigate threats by using Content Search
    - Three main locations to search:
	  1. Email
	  2. Documents
	  3. Instant messaging - Teams and O365 groups
  
  - Investigate threats by using Microsoft Graph activity logs
    - Two API versions - 1.0 and Beta
	- Know how to use the investigation graph
	- To create a rule:
	  - Overview page // Select and open Incident
	  - Incident page // Select the investigate button, or select investigate in Defender XDR Links
	  - Investigation graph // View the investigation graph

	| Area | Notes |
	|---|---|
	| xxxx | xxxx | 


- **Respond to incidents in Microsoft Sentinel**
  - Investigate and remediate incidents in Microsoft Sentinel
    - Three types of information provided to respond to incidents
	  1. Status
	  2. Severity
	  3. Ownership
	- Three steps to respond to incidents in Sentinel
	  1. Triage
	  2. Investigate
	  3. Resolve
	  
  - Create and configure automation rules
  - Create and configure Microsoft Sentinel playbooks
    - Create:
	  1. Select: Sentinel > Configuration > Automation 
	  2. Select: Create > Add new playbook
	  3. Configure settings in the tabs / panels that follow
	- Assign the playbook to an existing incident:
	  1. Select: Sentinel > Overview page > Threat Management > Incidents
	  2. Configure settings in the: Incidents page + Alert playbook page
	  
  - Run playbooks on on-premises resources


	| Area | Notes |
	|---|---|
	| xxxx | xxxx | 


## Implement and use Microsoft Security Copilot

- **Create and use promptbooks**
- **Manage sources for Security Copilot, including plugins and files**
  - Plugins
	- By default, only 'Owners' can add custom plugins
    - Format suppored: YAML (.yaml or .yml) or JSON (.json) formatted
  - File uploads: Select Upload file, then Add 
    - Max file size per file: 3 MB
    - Max file size for all files: 20 MB
    - File extensions supported: DOCX, MD, PDF, and TXT formats,
- **Integrate Security Copilot by implementing connectors**

- **Manage permissions and roles in Security Copilot**
  - Select Owner menu > Role assignment
- **Monitor Security Copilot capacity and cost**
  - To view usage: Select Owner menu > Usage monitoring
  - To change capacity: Select Owner menu > Owner settings > Switch Capacity
- **Identify threats and risks by using Security Copilot**
- **Investigate incidents by using Security Copilot**


## Manage security threats (15–20%)

- **Hunt for threats by using Microsoft Defender XDR**
  - Identify threats by using Kusto Query Language (KQL)
  - Interpret threat analytics in the Microsoft Defender portal
  - Create custom hunting queries by using KQL

	| Area | Notes |
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

	| Area | Notes |
	|---|---|
	| xxxx | xxxx | 


- **Create and configure Microsoft Sentinel workbooks**
  - Activate and customize workbook templates
  - Create custom workbooks that include KQL
  - Configure visualizations

	| Area | Notes |
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

### MISC Notes that need to be organized

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

- [Create an endpoint security policy](https://learn.microsoft.com/en-us/defender-endpoint/manage-security-policies#create-an-endpoint-security-policy)

Entra ID protections
 - Risky Users
 - Risky Sign-ins
 - Risky Apps
 
General exam tips to know:
 - Default values, minimum values, prerequisites, and licensing for all features and products in the stack.
 - Microsoft reccomendations on the use of these products.
 - Understanding of Azure roles and permissions needed for each product
