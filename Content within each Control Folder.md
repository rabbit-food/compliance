# CCI Dashboards and Visualizations

Below is a description of each CCI covered in this project, what the dashboards monitor, and how to use the visualizations.

## AC-3: Access Enforcement

### CCI-000213: Enforce Approved Authorizations
* **RMF Description:** This control requires the system to enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.
* **Dashboard Monitoring:** This dashboard monitors for **unauthorized access attempts**. It uses a machine learning (ML) job to detect unusual spikes in such attempts, which could indicate targeted attacks or misconfigurations. The visualizations provide a health status based on anomaly scores, a detailed breakdown of anomalies, and a granular view of individual unauthorized access events.
* **How to Use:** To perform a component-level compliance assessment, use the global filters at the top of the dashboard (e.g., filter by `host.name`). A non-zero count in the "Total Unauthorized Access Attempts" visualization is an immediate indicator of a potential policy violation. Use the trend and detailed tables to investigate the context of each unauthorized event.

---

## AU-3: Content of Audit Records

* **CCI-000130, CCI-000131, CCI-000132, CCI-001487, CCI-001493, CCI-001494, CCI-001495, CCI-003831, CCI-003832:** These CCIs cover various aspects of audit record content, such as ensuring events are logged, records are complete, timestamps are from authoritative sources, and organization-defined information is included.
* **Dashboard Monitoring:** The dashboards for these CCIs provide a comprehensive view of audit event logs, allowing you to verify that the required content is being captured. They include visualizations for:
    * **Audit Event Log:** A detailed, searchable log of all audit events.
    * **Event Actions Breakdown:** A breakdown of the total count of different event actions over time.
    * **Events by Module:** The distribution of audit events by the reporting module (e.g., `auditbeat`, `winlogbeat`).
    * **ML - Event Actions with Low Volume:** Identifies specific `event.action` types that are exhibiting anomalously low counts, which could indicate a logging failure.

---

## AU-4: Audit Log Storage Capacity

* **CCI-001848: Inform organization-defined personnel or roles of an audit logging process failure**
    * **RMF Description:** This control is about ensuring that the actions of individual users can be uniquely traced.
    * **Dashboard Monitoring:** The dashboard monitors user activity to ensure traceability. It includes visualizations that show audit activity by user, a trend of user activity, and detailed user activity events. An ML job is used to detect **anomalous user activity**.
* **CCI-001849: Provide a warning to organization-defined personnel, roles, and/or locations within organization-defined time period when allocated audit record storage volume reaches organization-defined percentage of repository maximum audit record storage capacity**
    * **RMF Description:** This control requires the system to provide a warning when the allocated audit record storage volume reaches a certain percentage of the maximum storage capacity.
    * **Dashboard Monitoring:** The dashboard monitors the volume and types of all audited events. It includes visualizations showing the total number of audited events and the trend of audited events by type. An ML job detects anomalies in the volume and types of audited events, which could indicate that the audit system has been tampered with or that a denial-of-service attack on the audit log is occurring.

---

## AU-9: Protection of Audit Information

* **CCI-000162, CCI-000163, CCI-000164, CCI-001494, CCI-001495, CCI-003831, CCI-003832:** These CCIs cover the protection of audit information from unauthorized access, modification, and deletion.
* **Dashboard Monitoring:** The dashboards for these CCIs provide a comprehensive view of access attempts on audit information and tools. They include visualizations for:
    * **Total Audit Information Access Attempts:** A high-level metric of all access attempts (successful and failed).
    * **Audit Activity Outcome and Action Breakdown:** A breakdown of access, modification, and deletion attempts by outcome and action.
    * **Top Targeted Audit Resources:** The top audit files or processes that are subject to access, modification, or deletion attempts.
    * **ML - Detailed Audit Access Anomalies:** A detailed breakdown of the most significant anomalies related to audit information access.

---

## AU-11: Audit Record Retention

* **CCI-000167: Retain audit records for organization-defined time period to provide support for after-the-fact investigations of security incidents and to meet regulatory and organizational information retention requirements.**
    * **RMF Description:** This control requires that audit records are retained for a specific period.
    * **Dashboard Monitoring:** This dashboard helps you assess compliance by monitoring audit record retention. It includes visualizations for the newest and oldest audit records and a breakdown of retention by data source. ML jobs are used to detect anomalies in the ingestion rate of audit records and in the count of older records, which can indicate issues with retention.
* **CCI-000168: Protect audit information and audit tools from unauthorized access, modification, and deletion.**
    * **RMF Description:** This control requires that audit records in long-term storage are protected from unauthorized activity.
    * **Dashboard Monitoring:** This dashboard helps assess compliance by monitoring for unauthorized activity in long-term storage. An ML job learns the normal, authorized behavior of privileged users interacting with long-term audit storage and flags any unusual events.

---

## AU-12: Audit Generation

* **CCI-000169, CCI-000171, CCI-000172, CCI-001459, CCI-001910:** These CCIs cover various aspects of audit generation, such as providing audit reports, on-demand review and analysis, adjusting audit levels in response to risk, central management of audit records, and analysis for unusual activity.
* **Dashboard Monitoring:** The dashboards for these CCIs provide visualizations to track audit report generation, monitor for rare and unusual activity, and check for audit configuration drift. They include:
    * **Generated Audit Reports:** A detailed list of all generated audit reports.
    * **Audit Reports Generated by User:** A bar chart showing the number of reports generated by each user.
    * **Audit Event Generation Matrix by Host:** A heatmap showing which systems are generating key types of audit events.
    * **ML - Detailed Report Generation Anomalies:** A table with details of any anomalies detected in the audit report generation process.

---

## CA-5: Plan of Action and Milestones

### CCI-000265, CCI-000266, CCI-000267: POA&M Updates, Monitoring, and Corrective Actions
* **RMF Description:** This family of CCIs requires the organization to develop, document, and implement a Plan of Action and Milestones (POA&M) for all security weaknesses identified in the system. The POA&M must contain a schedule for corrective actions and a milestone to monitor progress.
* **Dashboard Monitoring:** This dashboard provides real-time health status for your POA&M process. It uses an ML job to detect unusual trends in security findings that should trigger POA&M updates. The visualizations provide an at-a-glance health score, a timeline of anomalies, and a detailed table for investigating specific findings.
* **How to Use:** Use the **ML - POA&M Findings Anomaly Health** metric as a primary indicator. If you see a yellow or red status, it means the rate of new security findings is outside the normal baseline, which could signify a serious problem or a new vulnerability that requires an official POA&M. Use the **ML - Detailed POA&M Findings Anomalies** table to get the specifics, including the host, user, and rule that triggered the anomaly, so you can update your POA&M accordingly.

---

## CA-7: Continuous Monitoring

### CCI-000279: Timely Security Report Generation
* **RMF Description:** The organization must generate and deliver security reports and other information to specific individuals or roles according to an established frequency.
* **Dashboard Monitoring:** The dashboard monitors for report generation events. It tracks the trend of report creation, identifies who is generating reports, and provides a detailed table of every report event.
* **ML Job:** `ca-7-cci-000279-report-generation-trend-job`: This job establishes a baseline for normal report generation activity. An anomaly score spike could mean that a scheduled report failed to run (a drop in activity) or that an unexpected report was generated (a spike).
* **How to Use:** Check the **Security Report Generation Trend** to verify that reports are being produced on schedule. If a report is expected daily but the trend shows a gap, it indicates a failure. The **Reports Generated by User** chart helps confirm that only authorized personnel are performing this function.

### CCI-002087: Monitor System Change Events
* **RMF Description:** This control mandates the monitoring of system changes on an ongoing basis to ensure that all changes are authorized and align with the system's security posture.
* **Dashboard Monitoring:** The dashboard visualizes and tracks changes related to software packages and services. It provides a timeline of all system change events and a detailed table for in-depth analysis.
* **ML Job:** `ca-7-cci-002087-system-change-events-job`: This job learns the normal pattern of system changes within your environment. A high anomaly score flags an unusual number of changes or an unexpected type of change (e.g., a new service being installed on a production server), which could be a sign of unauthorized activity.
* **How to Use:** The **System Change Events Over Time** chart is the best way to spot unusual change activity. If you see an unexplained spike, use the **Detailed System Change Events** table to find out exactly what happened, who was responsible, and whether the change was authorized.

### CCI-002088: Monitor Security Assessment Events
* **RMF Description:** The organization must monitor for security assessment-related events, such as vulnerability scans, compliance checks, or penetration testing activities, to ensure that the required assessments are being performed regularly.
* **Dashboard Monitoring:** This dashboard provides metrics on your security assessment program. It tracks the total number of hosts scanned, a breakdown of assessment coverage by host, and a detailed table of all assessment events.
* **ML Job:** `ca-7-cci-002088-security-assessment-events-job`: This job establishes a baseline for the frequency and volume of security assessment events. An anomaly could mean a scheduled scan failed to run or that an unauthorized assessment is being performed on the network.
* **How to Use:** Use the **Total Scanned Hosts** metric to quickly check if all expected hosts are being assessed. The **Assessment Coverage by Host** chart is a valuable tool for identifying blind spots in your monitoring. If a critical host is missing, it's a sign that your assessment coverage is not compliant.

### CCI-002090: Timely Alert Triage
* **RMF Description:** The organization must define and monitor the process for triaging and responding to security alerts within an organization-defined time period.
* **Dashboard Monitoring:** The dashboard provides a clear overview of your alert response process. It displays the total number of untriaged alerts, a trend of triaged versus untriaged alerts, and a detailed table of all untriaged alerts.
* **ML Job:** `ca-7-cci-002090-untriaged-alerts-trend-job`: This job creates a baseline for the normal number of untriaged alerts in the system. An anomaly score will alert you to an unusual increase in untriaged alerts, which could indicate a growing backlog or a major incident.
* **How to Use:** The **Total Untriaged Security Alerts** metric is your top-level KPI. A high number suggests a problem. Use the **Detailed Untriaged Security Alerts** table to see exactly which alerts are pending and prioritize them.

### CCI-003874: Monitor Software & Service Changes
* **RMF Description:** This control requires organizations to establish a software and service baseline and monitor all changes to that baseline on an ongoing basis.
* **Dashboard Monitoring:** The dashboard provides a comprehensive inventory of all installed software packages and services. It tracks system changes over time, including installations, deletions, and modifications.
* **ML Job:** `ca-7-cci-003874-software-service-change-trend-job`: This job learns the normal patterns of software and service changes in your environment. An anomaly score will alert you to unusual activity, such as an unauthorized software installation or a critical service being stopped.
* **How to Use:** Use the **System Software Inventory** and **System Service Inventory** tables to perform regular checks against your authorized baselines. If you see unexpected software or services, it's a compliance violation. The ML job helps you proactively find these changes and investigate them immediately.

### CCI-003875: Monitor Security Report Execution
* **RMF Description:** The organization must monitor the execution of all security reports and other security-related reporting activities, verifying that they are being run by authorized personnel.
* **Dashboard Monitoring:** This dashboard provides visibility into the execution of all security reports. It tracks who is running reports, shows the report execution trend, and provides a detailed table of every report execution event.
* **ML Job:** `ca-7-cci-003875-security-report-execution-job`: This job models the normal behavior of report execution. An anomaly here could mean a report was run by an unauthorized user or service account, or that a scheduled report failed to run at its appointed time.
* **How to Use:** The **Detailed Security Report Executions** table is your primary source for auditing who ran what report and when. Any event by an unauthorized user is a security event that needs to be addressed immediately.

### CCI-003876: Total Security Reports Generated
* **RMF Description:** The organization must monitor the total number of security reports generated and verify that the count aligns with the expected frequency and volume of reports.
* **Dashboard Monitoring:** The dashboard provides a high-level view of security reporting. It includes a metric for the total number of reports generated, a trend visualization, and a breakdown of reports by name.
* **ML Job:** `ca-7-cci-003876-total-security-reports-job`: This job tracks the overall volume of generated reports. Anomaly scores will alert you to unexpected increases or decreases in report volume, helping you identify a problem with your automated reporting processes.
* **How to Use:** Use the **Total Security Reports Generated** metric as a quick daily or weekly check. If a report that is supposed to run daily has a total count of less than 7 for the last week, it indicates a failure that needs to be investigated.

### CCI-003877: Monitor Security Report Generation Status
* **RMF Description:** The organization must monitor the status (e.g., success or failure) of all security report generation events.
* **Dashboard Monitoring:** The dashboard tracks the status of report generation events. It shows the trend of report generation, provides a breakdown of reports by name, and lists detailed events, including the outcome.
* **ML Job:** `ca-7-cci-003877-security-report-generation-status-job`: This job models the normal success and failure rates for report generation. An anomaly could mean a specific report is failing at a higher rate than normal, which could indicate a misconfiguration.
* **How to Use:** Use the visualizations to confirm that all reports are completing successfully. If you see failures, use the detailed tables to investigate the reasons for the failure and remediate the underlying issue.

### CCI-003878: Monitor Data Source Diversity
* **RMF Description:** The organization must monitor the diversity of its data sources and ensure that data is being collected from all relevant systems and platforms.
* **Dashboard Monitoring:** The dashboard provides a high-level overview of your data collection. It tracks the total number of unique data sources, the total number of unique operating system families, and a trend of log ingestion by data source.
* **ML Jobs:**
    * `ca-7-cci-003878-data-source-diversity-trend-job`: This job tracks the unique number of data sources. Anomaly scores here will alert you if a source suddenly stops sending data.
    * `ca-7-cci-003878-os-family-diversity-trend-job`: This job monitors the diversity of operating system families. Anomaly scores here could mean that a group of hosts has stopped sending logs.
* **How to Use:** Check the **Data Source Diversity** and **OS Family Diversity** metrics to ensure all expected sources are reporting. A drop in either metric is a red flag. The **Data Ingestion Trend** chart helps you identify when and which data source stopped reporting so you can investigate and restore the connection.

---

## IR-5: Incident Monitoring

### CCI-000832: Incident Tracking and Documentation
* **RMF Description:** The organization must establish and document a process for tracking and documenting security incidents from detection to resolution.
* **Dashboard Monitoring:** This dashboard provides a complete overview of your incident response pipeline. It monitors for all incoming security signals, shows the volume of documented cases, and identifies a backlog of unaddressed alerts. It also uses ML jobs to detect unusual spikes in signal volume, high-severity events, or noisy hosts that could indicate a problem.
* **How to Use:** The **Incident Monitoring ML Score** is your overall health indicator. If it's anything but green, investigate immediately. The **Incoming Security Signals Trend** shows the raw volume of alerts, helping you spot potential attacks. The **Signal Documentation Status** chart gives a quick visual of your team's workload. For deep dives, use the **Detailed Signal and Case Log** to see which specific signals are not being documented and investigate why.

---

## PL-2: System Security Plan

### CCI-003063: Plan Protection (Unauthorized Access)
* **RMF Description:** The organization must protect its security and system plans from unauthorized disclosure. This includes monitoring for unauthorized access attempts to the digital repositories where these documents are stored.
* **Dashboard Monitoring:** This dashboard monitors and visualizes all access attempts on files with common security plan names and extensions. It shows a trend of unauthorized access attempts, a breakdown of these attempts by user, and a detailed table of every access event.
* **ML Job:** `pl-2-cci-003063-unauthorized-plan-access-trend-job`: This job learns the normal baseline of access attempts on plan repositories. Anomaly scores will alert you to unusual spikes in activity, which could indicate an outsider trying to steal plans or an insider attempting to access unauthorized information.
* **How to Use:** Use the **Unauthorized Plan Access Attempts Trend** to spot any unexpected spikes. The **Unauthorized Plan Access by User** chart quickly identifies which accounts are behind the activity. For investigation, use the **Detailed Plan Access Events** table to verify if the event was a legitimate action or a policy violation.

### CCI-003064: Plan Protection (Unauthorized Modification)
* **RMF Description:** The organization must protect its security and system plans from unauthorized modification.
* **Dashboard Monitoring:** This dashboard uses a file integrity monitoring (FIM) approach to track changes on critical plan documents. It displays the total number of unauthorized modifications, a trend of these attempts, and a detailed table of every modification event.
* **ML Job:** `pl-2-cci-003064-unauthorized-plan-modification-trend-job`: This job creates a baseline of changes to plan documents, which should be very low or non-existent. Any spike in the anomaly score is a high-priority alert, indicating a modification attempt that needs to be investigated immediately.
* **How to Use:** The **Total Unauthorized Plan Modifications** metric should be zero. Any number above zero is a compliance failure. Use the **Unauthorized Plan Modification Trend** to see when the activity occurred and the **Detailed Unauthorized Plan Modification Events** table to find out who made the change, what was changed, and whether the change was authorized.

---

## PM-4: Plan of Action and Milestones (POA&M)

### CCI-004326: Vulnerability Management
* **RMF Description:** This control requires the organization to mitigate known vulnerabilities in a timely manner. It's about ensuring your vulnerability management program is effective and that discovered vulnerabilities are being addressed.
* **Dashboard Monitoring:** This dashboard provides a comprehensive view of your vulnerability management program. It leverages data from vulnerability scanners to show metrics on open critical and high-severity vulnerabilities, visualizes remediation trends, and identifies the most vulnerable hosts.
* **ML Jobs:**
    * `pm-4-cci-004326-high-vuln-count-host`: Detects hosts that have an unusually high count of open vulnerabilities.
    * `pm-4-cci-004326-new-critical-high-vuln-spike`: Alerts on unexpected spikes in new critical or high-severity vulnerabilities.
    * `pm-4-cci-004326-remediation-rate-per-host`: Monitors the rate at which vulnerabilities are being fixed versus discovered.
* **How to Use:** The **ML - Vulnerability Management Health Status** metric provides an at-a-glance overview of your entire program. A non-green status indicates a major issue. Use the **Open Critical Vulnerabilities** and **Open High Vulnerabilities** metrics to identify your biggest risks. The **Vulnerability Remediation Trend** helps you prove that you're fixing vulnerabilities faster than new ones are being discovered.

---

## PM-5: Asset Inventory

### CCI-004328, CCI-004329: Develop and Update System Inventory
* **RMF Description:** This control requires the organization to develop and maintain an accurate and up-to-date inventory of all organizational systems. It's about discovering all assets and ensuring that they are continuously monitored.
* **Dashboard Monitoring:** This dashboard is a foundational tool for asset inventory management. It uses data from all logging agents to build a dynamic inventory of every system reporting to Elasticsearch. It tracks new hosts appearing on the network, hosts that stop reporting, and identifies unexpected operating systems.
* **ML Jobs:**
    * `pm-5-cci-004328-004329-new-hosts-trend-job`: Detects sudden spikes in new hosts, which could indicate unauthorized devices or provisioning issues.
    * `pm-5-cci-004328-rare-os-detection-job`: Flags the appearance of new or rare operating systems that deviate from your established baseline.
    * `pm-5-cci-004328-004329-hosts-stopped-reporting-job`: Alerts you when a host that normally reports stops sending data.
* **How to Use:** Use the **Total Discovered Systems** metric and the **Reporting Host Inventory** table to compare your detected systems against your official Configuration Management Database (CMDB). Any discrepancy is a key finding. A spike in the **ML - New Hosts Anomaly Score Trend** signals a potential policy violation that needs to be investigated immediately to maintain an accurate inventory.

---

## PM-6: Security and Privacy Performance Measures

### CCI-000210: Identify Security Events
* **RMF Description:** This control requires the organization to develop a list of key security events that must be monitored.
* **Dashboard Monitoring:** The dashboard for this CCI is designed to provide a comprehensive, top-level view of all security-related events across the enterprise. It provides the foundation for defining and monitoring what constitutes a key security event within your organization's environment.
* **How to Use:** This dashboard is essentially a template. You would populate it with visualizations of specific security events relevant to your organization's policy. For example, you would add charts for critical alerts, high-severity vulnerabilities, or specific authentication failures to track and verify that they are being monitored.

### CCI-000211: Reportable Security Incidents
* **RMF Description:** This control requires the organization to define and monitor for security incidents that must be reported to designated personnel. This goes beyond raw events to focus on what truly constitutes an incident.
* **Dashboard Monitoring:** The dashboard is designed to be a reporting tool for security incidents. It relies on an ML job to identify anomalous increases in events that are classified as "reportable" based on your organization's policy.
* **ML Job:** `pm-6-cci-000211-reportable-incidents-trend-job`: This job detects abnormal spikes in incidents that your policy defines as reportable. This could include a surge of high-severity alerts or multiple, successful privilege escalation attempts.
* **How to Use:** This dashboard is your primary tool for validating that the events you consider "reportable" are being correctly identified and monitored. The ML job helps you find anomalous patterns in these events, which can be used to generate reports for stakeholders as required by the control.

### CCI-004336: Report Sensitive Data Access
* **RMF Description:** This control requires organizations to monitor and report on unauthorized access to sensitive data (e.g., PII, PHI, financial data).
* **Dashboard Monitoring:** This dashboard focuses on protecting sensitive data by monitoring access to files and paths that contain this data. It tracks access trends and identifies which users are interacting with sensitive information.
* **ML Job:** `pm-6-cci-004336-sensitive-data-access-trend-job`: This job creates a baseline of normal access patterns to sensitive data. Anomalies are detected when a user accesses sensitive data more frequently than usual, or if a user who typically never accesses this data suddenly does.
* **How to Use:** Use the visualizations to identify unexpected access to sensitive data. A high anomaly score from the ML job is a strong signal for a potential data breach or policy violation. Use the detailed tables to investigate the user, host, and file path involved to determine if a formal report is required.

### CCI-004337: Report Privacy Incidents
* **RMF Description:** This control requires the organization to define, track, and report on privacy-related events or incidents.
* **Dashboard Monitoring:** This dashboard provides a comprehensive overview of your privacy incident monitoring program. It tracks the total volume and trends of privacy-related incidents, such as DLP alerts, and identifies the key influencers behind any anomalies.
* **ML Job:** `pm-6-cci-004337-privacy-incidents-trend-job`: This job learns the normal pattern of privacy-related events. Anomaly scores here will alert you to unusual spikes in activity, helping you detect potential data leaks or policy violations that need to be reported to stakeholders.
* **How to Use:** The **Total Privacy Incidents** metric is your main KPI. An unexpected increase in this number should prompt you to use the other visualizations, like the **Privacy Incident Trend** and the **Top Privacy Incident Anomaly Influencers** table, to investigate the root cause and prepare a performance report as required.

---

## RA-3: Risk Assessment

### CCI-001048: Determine Likelihood and Magnitude of Harm
* **RMF Description:** The organization must define and document a process for determining the likelihood and potential magnitude of harm for security events. The goal is to prioritize risks and ensure that critical events are responded to appropriately.
* **Dashboard Monitoring:** This dashboard provides a data-driven approach to risk assessment by monitoring for high-severity events that are proxies for high-impact security incidents. It uses an ML job to detect an unusual number of failures, alerts, and signals. The visualizations include a health status metric, a trend chart for high-severity events, a risk matrix to identify the riskiest hosts, and a detailed table of all risk assessment events.
* **How to Use:** Use the **Host Risk Matrix** to quickly identify which hosts are experiencing the most frequent and severe security events. A dark cell in this matrix indicates a high risk that should be investigated immediately. The **ML - High Severity Events Health Status** is your top-level indicator. Any non-green score signals a deviation from the normal baseline. Use the **Detailed Risk Assessment Events** table to get the raw data you need to assess the likelihood and magnitude of harm for a specific event.

### CCI-001050: Review Risk Assessment Results
* **RMF Description:** The organization must review risk assessment results on a defined frequency to ensure that the risk posture is continuously understood and addressed.
* **Dashboard Monitoring:** This dashboard provides a dynamic view of your risk posture, leveraging security signals to give a real-time assessment. It includes a metric for the number of open signals, a trend chart of risk over time, and a chart identifying the top risky hosts.
* **ML Job:** `ra-3-cci-001050-004618-new-security-signals-trend`: This job detects unusual patterns in new security signals. A high anomaly score could indicate a new threat has emerged or is being actively exploited, which requires an update to your risk assessment.
* **How to Use:** Monitor the **Overall Risk Score (Open Signals)** metric to track your organization's total risk. A high or increasing number is a call to action. The **Risk Trend Over Time** chart helps you understand if your efforts are succeeding. Use the **Top Risky Hosts by Open Signals** chart to prioritize which systems need your immediate attention.

### CCI-001052: Update Risk Assessment
* **RMF Description:** The organization must update its risk assessment when significant changes occur to the system, such as new software installations, configuration changes, or new threats being identified.
* **Dashboard Monitoring:** This dashboard tracks a variety of significant system changes. It includes a trend chart of these changes over time, a breakdown of changes by category, and a detailed table of all change events.
* **ML Job:** `ra-3-cci-001052-significant-system-changes-trend`: This job learns the normal pattern of system changes and flags anything that deviates from this baseline. A high anomaly score could be due to unauthorized software installations, unexpected privilege changes, or modifications to critical system files.
* **How to Use:** Use the **Significant System Change Trend** chart to identify spikes in change events. If a spike occurs, use the **System Change Breakdown** chart to see the type of change (e.g., vulnerability, iam, package). This helps you quickly pinpoint which changes need to be correlated with change management tickets or investigated as a security incident.

### CCI-004618: Identify Threats
* **RMF Description:** The organization must actively identify and document threats to its systems and information.
* **Dashboard Monitoring:** This dashboard leverages security information and event management (SIEM) signals to provide a real-time view of the threat landscape. It includes a metric for total active threats, a trend of threat identification by severity, and a detailed table of all threat events.
* **ML Job:** `ra-3-cci-001050-004618-new-security-signals-trend`: This job is shared with CCI-001050. It detects unusual volumes or types of new security signals. An anomaly indicates a new or emerging threat has been identified.
* **How to Use:** The **Total Active Threats** metric is your main KPI. A high number means a lot of alerts are open and need attention. The **Threat Identification Trend by Severity** chart helps you prioritize, showing if you have a surge of high or critical alerts. The **Detailed Threat Events** table provides the raw data to investigate the threats, including the `rule.name`, `host.name`, and `user.name` involved.

### CCI-004619: Identify Vulnerabilities
* **RMF Description:** The organization must continuously identify vulnerabilities in its systems to inform its risk management process.
* **Dashboard Monitoring:** This dashboard provides a single pane of glass for all vulnerability data. It displays a health status based on ML jobs, shows the trend of new vulnerabilities, and provides a detailed listing of all vulnerabilities.
* **ML Job:** `ra-3-cci-004619-new-vulnerabilities-trend`: This job detects unusual spikes in new vulnerability findings on a per-host basis. An anomaly score here could mean a new, widespread vulnerability has been discovered or that a scan has misfired.
* **How to Use:** The **ML - New Vulnerabilities Health Status** is your high-level health check. The **Top 10 Vulnerable Hosts** chart helps you prioritize your remediation efforts. The **Vulnerability Discovery Trend** shows if you are finding more vulnerabilities than normal, which could indicate a new threat. The **Detailed Vulnerability Listings** table is your primary tool for investigating and managing individual vulnerabilities.

### CCI-004620: Determine Likelihood and Impact for PII
* **RMF Description:** This control requires the organization to conduct a risk assessment on the processing of Personally Identifiable Information (PII) to determine the likelihood and impact of privacy incidents.
* **Dashboard Monitoring:** This dashboard focuses on monitoring access to PII. It tracks the trend of PII access, identifies the top users accessing this data, and uses an ML job to detect unusual access patterns.
* **ML Job:** `ra-3-cci-004620-pii-access-trend`: This job learns the normal access patterns for PII. Anomalies are triggered when a user accesses PII more frequently than usual, from an unexpected location, or uses an unusual process. This is a crucial control for detecting potential data exfiltration or insider threats.
* **How to Use:** The **PII Access Trend** is your primary tool for monitoring for a spike in activity. Use the **Top Users Accessing PII** chart to identify who is most active. A high anomaly score from the ML job is a strong signal for a potential privacy incident. The **Detailed PII Access Events** table provides the granular details needed for an investigation, allowing you to determine the likelihood and impact of the event.