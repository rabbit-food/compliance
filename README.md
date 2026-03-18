# RMF, FedRAMP, CMMC, C-SCRM, NIST, Visualizations, ML Jobs, and Dashboards for Kibana and Elastic

This project provides a set of Kibana visualizations, machine learning jobs, and dashboards specifically designed for cyber compliance frameworks. Most of these frameworks utilize the same Controls. The goal of these tools is to enable real-time monitoring of cyber compliance policy at the component level within an Elastic and Kibana environment.

- **Risk Management Framework (RMF)** **NIST 800-53r5**
- **Cybersecurity Maturity Model Certification (CMMC) v2.0**
- **NIST 800-171r3**
- **Cybersecurity Supply Chain Risk Management (C-SCRM)**
- **NIST 800-161r1**
- **Federal Risk and Authorization Management Program (FedRAMP)** **NIST 800-53r5**

Check out our [LinkedIn page](https://www.linkedin.com/company/rabbitfooddod) for updates, demo's, and discussion

![Main Dashboard](images/%20Main%20Dashboard%20View.png)
![Drill Down to CCI View](images/CCI%20View.png)


## Disclaimer

**There is currently no official support for these visualizations, ML jobs, and dashboards. Use them at your own risk.**
We highly appreciate any bug reports and pull requests for fixes. Your contributions are valuable to the community and will help improve these tools for everyone.
While these dashboards and visualizations are powerful for ongoing assessment, they are not intended to replace the full RMF process.

##

### For RMF Compliance Monitoring : How to use these 

Use as-is. 

At this time these visualizations are categorized under the format of the RMF. This repo's tools are primarily designed to assist with Federal compliance **continuous monitoring** and the federal compliance frameworks are all built off of one another. They provide real-time insights into your security posture and help you determine if specific **Control Correlation Identifiers (CCIs)** are being met for each individual component you need to monitor.

While these dashboards and visualizations are powerful for ongoing assessment, they are not intended to replace the full RMF process.

A description of all dashboads in this github can be found in the file [Content within each Control folder](Content%20within%20each%20Control%20Folder.md) This will describe what each dashboard, ml job, and visualization will provide for each CCI and Control



### For CMMC Compliance Monitoring : How to use these 

Use this: [Protoype CUI Overlay](https://csrc.nist.gov/files/pubs/sp/800/171/r3/fpd/docs/sp800-171r3-fpd-cui-overlay.xlsx)

This repo's tools are primarily designed to assist with Federal compliance **continuous monitoring** and the federal compliance frameworks are all built off of one another. At this time the repo's visualizations are categorized under the format of the RMF but they are VERY similar (basically exact) requirements for CMMC.  The government provided this link to show which RMF ID's match the CMMC ID's. You can use this to connect the RMF format of this repo.



### For C-SCRM Compliance Monitoring : How to use these 

Use this: [Protoype CUI Overlay](https://csrc.nist.gov/files/pubs/sp/800/171/r3/fpd/docs/sp800-171r3-fpd-cui-overlay.xlsx)

This repo's tools are primarily designed to assist with Federal compliance **continuous monitoring** and the federal compliance frameworks are all built off of one another. At this time the repo's visualizations are categorized under the format of the RMF but they are VERY similar (basically exact) requirements for C-SCRM.  Any C-SCRM function similar to CMMC uses a nearly identically ID and definition to the equivalent CMMC ID. In future versions I might show this via a spreadsheet. Anyway, the federal priority for C-SCRM is new, they have not put in the time to build a method to match their C-SCRM ID's to RMF. So for now use the above CMMC link as it is nearly identical

##
## Getting Started
##

### Prerequisites

* An up-and-running **Elasticsearch** and **Kibana** environment.
* Data flowing into Elasticsearch, preferably following the **Elastic Common Schema (ECS)**.

### Data View Configuration

The visualizations and dashboards in this project use **`logs-*`** as the default data view. If your organization uses a different data view (e.g., `audit*`), you will need to update the data view for the visualizations to function correctly. This can be done within Kibana's "Saved Objects" section by editing the individual visualizations and dashboards.

### Loading Kibana Objects

Each CCI has a corresponding `.ndjson` file that contains the Kibana dashboards and visualizations.

1.  In Kibana, navigate to **Management > Stack Management > Saved Objects**.
2.  Click the **Import** button.
3.  Select the `.ndjson` file for the CCI you want to load.
4.  Click **Import**.

It is recommended to **pick and choose which CCIs are valuable to you** and load those in individually, rather than importing everything at once.

### Loading Machine Learning Jobs

The machine learning jobs are provided in `.txt` files. These contain the API calls to create and start the ML jobs.

1.  In Kibana, navigate to **Management > Dev Tools**.
2.  Open the `.txt` file for the ML job you want to load (e.g., `ac-3-ML-Jobs.txt`).
3.  Copy and paste the API calls from the text file into the Dev Tools console.
4.  Run the commands.

**To assess if the ML jobs were loaded correctly:**

1.  Navigate to **Machine Learning > Anomaly Detection**.
2.  You should see the newly created jobs in the list.
3.  Verify that the jobs are running and processing data. It may take some time for the jobs to learn the baseline behavior of your data and produce meaningful results.


## How to Use the Visualizations

Each dashboard is designed to provide as much detail as possible in a simple and pleasant-to-read way. As an RMF analyst, you can use the global filters at the top of each Kibana dashboard to drill down into specific components. For example, you can filter by `host.name` to see the data for a single server.

By analyzing the visualizations for each component, you can come to a conclusion about whether that specific CCI is being met.

## Machine Learning Jobs and Alerting

The goal of the machine learning jobs is to show changes to any monitored issues. At this time, we have not built alerts on top of these ML jobs because that could be too complex in environments with many moving parts. However, you can view any changes to the monitored items in a Control and build your own alerts off of those.
