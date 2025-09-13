{\rtf1\ansi\ansicpg1252\cocoartf2822
\cocoatextscaling0\cocoaplatform0{\fonttbl\f0\fswiss\fcharset0 Helvetica;}
{\colortbl;\red255\green255\blue255;}
{\*\expandedcolortbl;;}
\margl1440\margr1440\vieww11520\viewh8400\viewkind0
\pard\tx720\tx1440\tx2160\tx2880\tx3600\tx4320\tx5040\tx5760\tx6480\tx7200\tx7920\tx8640\pardirnatural\partightenfactor0

\f0\fs24 \cf0 # RMF Visualizations, ML Jobs, and Dashboards for Kibana and Elastic\
\
This project provides a set of Kibana visualizations, machine learning jobs, and dashboards specifically designed for **Risk Management Framework (RMF) analysts**. The goal of these tools is to enable real-time monitoring of RMF policy compliance at the component level within an Elastic and Kibana environment.\
\
***\
\
## \uc0\u55357 \u56540  Disclaimer\
\
> **There is currently no official support for these visualizations, ML jobs, and dashboards. Use them at your own risk.**\
>\
> We highly appreciate any bug reports and pull requests for fixes. Your contributions are valuable to the community and will help improve these tools for everyone.\
\
***\
\
## RMF Compliance Monitoring\
\
These tools are primarily designed to assist with the **continuous monitoring** aspects of the RMF. They provide real-time insights into your security posture and help you determine if specific **Control Correlation Identifiers (CCIs)** are being met for each individual component you need to monitor.\
\
While these dashboards and visualizations are powerful for ongoing assessment, they are not intended to replace the full RMF process.\
\
***\
\
## \uc0\u55357 \u56960  Getting Started\
\
### Prerequisites\
\
* An up-and-running **Elasticsearch** and **Kibana** environment.\
* Data flowing into Elasticsearch, preferably following the **Elastic Common Schema (ECS)**.\
\
### Data View Configuration\
\
The visualizations and dashboards in this project use **`logs-*`** as the default data view. If your organization uses a different data view (e.g., `audit*`), you will need to update the data view for the visualizations to function correctly. This can be done within Kibana's "Saved Objects" section by editing the individual visualizations and dashboards.\
\
### Loading Kibana Objects\
\
Each CCI has a corresponding `.ndjson` file that contains the Kibana dashboards and visualizations.\
\
1.  In Kibana, navigate to **Management > Stack Management > Saved Objects**.\
2.  Click the **Import** button.\
3.  Select the `.ndjson` file for the CCI you want to load.\
4.  Click **Import**.\
\
It is recommended to **pick and choose which CCIs are valuable to you** and load those in individually, rather than importing everything at once.\
\
### Loading Machine Learning Jobs\
\
The machine learning jobs are provided in `.txt` files. These contain the API calls to create and start the ML jobs.\
\
1.  In Kibana, navigate to **Management > Dev Tools**.\
2.  Open the `.txt` file for the ML job you want to load (e.g., `ac-3-ML-Jobs.txt`).\
3.  Copy and paste the API calls from the text file into the Dev Tools console.\
4.  Run the commands.\
\
**To assess if the ML jobs were loaded correctly:**\
\
1.  Navigate to **Machine Learning > Anomaly Detection**.\
2.  You should see the newly created jobs in the list.\
3.  Verify that the jobs are running and processing data. It may take some time for the jobs to learn the baseline behavior of your data and produce meaningful results.\
\
***\
\
## CCI Dashboards and Visualizations\
\
Below is a description of each CCI covered in this project, what the dashboards monitor, and how to use the visualizations.\
\
### AC-3: Access Enforcement\
\
#### CCI-000213: Enforce Approved Authorizations\
* **RMF Description:** This control requires the system to enforce approved authorizations for logical access to information and system resources in accordance with applicable access control policies.\
* [cite_start]**Dashboard Monitoring:** This dashboard monitors for unauthorized access attempts[cite: 10, 12, 14, 17, 20]. [cite_start]It uses a machine learning job to detect unusual spikes in such attempts, which could indicate targeted attacks or misconfigurations[cite: 2]. [cite_start]The visualizations provide a health status based on anomaly scores, a detailed breakdown of anomalies, and a granular view of individual unauthorized access events[cite: 2, 4, 7, 23, 25, 28].\
* [cite_start]**How to Use:** To perform a component-level compliance assessment, use the global filters at the top of the dashboard (e.g., filter by `host.name`)[cite: 2, 11, 31]. [cite_start]A non-zero count in the "Total Unauthorized Access Attempts" visualization is an immediate indicator of a potential policy violation[cite: 18, 32, 36]. [cite_start]Use the trend and detailed tables to investigate the context of each unauthorized event[cite: 12, 21, 29].\
\
### AU-3: Content of Audit Records\
\
* **CCI-000130, CCI-000131, CCI-000132, CCI-001487, CCI-001493, CCI-001494, CCI-001495, CCI-003831, CCI-003832:** These CCIs cover various aspects of audit record content, such as ensuring events are logged, records are complete, timestamps are from authoritative sources, and organization-defined information is included.\
* **Dashboard Monitoring:** The dashboards for these CCIs provide a comprehensive view of audit event logs, allowing you to verify that the required content is being captured. They include visualizations for:\
    * [cite_start]**Audit Event Log:** A detailed, searchable log of all audit events[cite: 305, 324].\
    * [cite_start]**Event Actions Breakdown:** A breakdown of the total count of different event actions over time[cite: 315].\
    * [cite_start]**Events by Module:** The distribution of audit events by the reporting module (e.g., auditbeat, winlogbeat)[cite: 320].\
    * [cite_start]**ML - Event Actions with Low Volume:** Identifies specific `event.action` types that are exhibiting anomalously low counts, which could indicate a logging failure[cite: 309].\
\
### AU-4: Audit Log Storage Capacity\
\
* **CCI-001848: Inform organization-defined personnel or roles of an audit logging process failure**\
    * **RMF Description:** This control is about ensuring that the actions of individual users can be uniquely traced.\
    * [cite_start]**Dashboard Monitoring:** The dashboard monitors user activity to ensure traceability[cite: 540, 564]. [cite_start]It includes visualizations that show audit activity by user, a trend of user activity, and detailed user activity events[cite: 541, 551, 557, 565, 568]. [cite_start]A machine learning job is used to detect anomalous user activity[cite: 546, 549].\
* **CCI-001849: Provide a warning to organization-defined personnel, roles, and/or locations within organization-defined time period when allocated audit record storage volume reaches organization-defined percentage of repository maximum audit record storage capacity**\
    * **RMF Description:** This control requires the system to provide a warning when the allocated audit record storage volume reaches a certain percentage of the maximum storage capacity.\
    * [cite_start]**Dashboard Monitoring:** The dashboard monitors the volume and types of all audited events[cite: 574, 582, 586, 590, 593]. [cite_start]It includes visualizations showing the total number of audited events and the trend of audited events by type[cite: 574, 587]. [cite_start]A machine learning job detects anomalies in the volume and types of audited events, which could indicate that the audit system has been tampered with or that a denial-of-service attack on the audit log is occurring[cite: 578].\
\
### AU-9: Protection of Audit Information\
\
* **CCI-000162, CCI-000163, CCI-000164, CCI-001494, CCI-001495, CCI-003831, CCI-003832:** These CCIs cover the protection of audit information from unauthorized access, modification, and deletion.\
* **Dashboard Monitoring:** The dashboards for these CCIs provide a comprehensive view of access attempts on audit information and tools. They include visualizations for:\
    * [cite_start]**Total Audit Information Access Attempts:** A high-level metric of all access attempts (successful and failed)[cite: 615, 695, 725, 775, 822, 1012].\
    * [cite_start]**Audit Activity Outcome and Action Breakdown:** A breakdown of access, modification, and deletion attempts by outcome and action[cite: 621, 701, 769, 852, 909, 931, 958, 998, 1025, 1062, 1093, 1121].\
    * [cite_start]**Top Targeted Audit Resources:** The top audit files or processes that are subject to access, modification, or deletion attempts[cite: 627, 633, 714, 763, 840, 903, 964].\
    * [cite_start]**ML - Detailed Audit Access Anomalies:** A detailed breakdown of the most significant anomalies related to audit information access[cite: 642, 689, 723, 761, 785, 829].\
\
### AU-11: Audit Record Retention\
\
* **CCI-000167: Retain audit records for organization-defined time period to provide support for after-the-fact investigations of security incidents and to meet regulatory and organizational information retention requirements.**\
    * **RMF Description:** This control requires that audit records are retained for a specific period.\
    * [cite_start]**Dashboard Monitoring:** This dashboard helps you assess compliance by monitoring audit record retention[cite: 55]. [cite_start]It includes visualizations for the newest and oldest audit records, and a breakdown of retention by data source[cite: 56, 60, 67, 72, 74, 77]. [cite_start]Machine learning jobs are used to detect anomalies in the ingestion rate of audit records and in the count of older records, which can indicate issues with retention[cite: 52, 64].\
* **CCI-000168: Protect audit information and audit tools from unauthorized access, modification, and deletion.**\
    * **RMF Description:** This control requires that audit records in long-term storage are protected from unauthorized activity.\
    * [cite_start]**Dashboard Monitoring:** This dashboard helps assess compliance by monitoring for unauthorized activity in long-term storage[cite: 84, 85]. [cite_start]A machine learning job learns the normal, authorized behavior of privileged users interacting with long-term audit storage and flags any unusual events[cite: 80, 81].\
\
### AU-12: Audit Generation\
\
* **CCI-000169, CCI-000171, CCI-000172, CCI-001459, CCI-001910:** These CCIs cover various aspects of audit generation, such as providing audit reports, on-demand review and analysis, adjusting audit levels in response to risk, central management of audit records, and analysis for unusual activity.\
* **Dashboard Monitoring:** The dashboards for these CCIs provide visualizations to track audit report generation, monitor for rare and unusual activity, and check for audit configuration drift. They include:\
    * [cite_start]**Generated Audit Reports:** A detailed list of all generated audit reports[cite: 120, 137].\
    * [cite_start]**Audit Reports Generated by User:** A bar chart showing the number of reports generated by each user[cite: 123, 140].\
    * [cite_start]**Audit Event Generation Matrix by Host:** A heatmap showing which systems are generating key types of audit events[cite: 127, 144].\
    * [cite_start]**ML - Detailed Report Generation Anomalies:** A table with details of any anomalies detected in the audit report generation process[cite: 118, 133].\
\
***\
\
## How to Use the Visualizations\
\
Each dashboard is designed to provide as much detail as possible in a simple and pleasant-to-read way. As an RMF analyst, you can use the global filters at the top of each Kibana dashboard to drill down into specific components. For example, you can filter by `host.name` to see the data for a single server.\
\
By analyzing the visualizations for each component, you can come to a conclusion about whether that specific CCI is being met.\
\
## Machine Learning Jobs and Alerting\
\
The goal of the machine learning jobs is to show changes to any monitored issues. At this time, we have not built alerts on top of these ML jobs because that could be too complex in environments with many moving parts. However, you can view any changes to the monitored items in a Control and build your own alerts off of those.}