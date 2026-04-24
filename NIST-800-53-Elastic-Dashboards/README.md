

Step 1: Create the ML Data View

Before importing a dashboard, Kibana needs to know where to pull the ML results from.

1. Go to Stack Management > Data Views.
2. Click Create data view.
3. Name: siem-ml-job-results
4. Index pattern: .ml-anomalies-* (Toggle "Include system and hidden indices" if it doesn't show up).
5. Timestamp field: timestamp (Note: ML results use timestamp, not @timestamp).
6. Save it.
