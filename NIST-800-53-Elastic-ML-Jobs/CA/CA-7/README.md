# Consolidated Risk Score Example

To tie these four jobs together for CCI-003883, we use an Elastic Transform. This takes the individual anomaly signals (the "siloed" activities) and pivots them into a single, continuous Risk Entity Scorecard.

This satisfies the CCI requirement that risk monitoring be "woven into the broader continuous monitoring program" by creating a unified view of your risk posture.

## The Strategy

We will pivot on host.name (or user.name) to aggregate the maximum anomaly score from each of your four categories over a specific timeframe (e.g., daily).

## 1. Transform Configuration (JSON)
This creates a new index called ca-7-cci-003883-risk-posture-summary.

{
  "id": "ca-7-cci-003883-consolidated-risk-transform",
  "source": {
    "index": [".ml-anomalies-shared"] 
  },
  "dest": {
    "index": "ca-7-cci-003883-risk-posture-summary"
  },
  "pivot": {
    "group_by": {
      "timestamp": {
        "date_histogram": {
          "field": "timestamp",
          "calendar_interval": "1d"
        }
      },
      "entity_id": {
        "terms": {
          "field": "partition_field_value" 
        }
      }
    },
    "aggregations": {
      "system_config_risk": {
        "filter": { "term": { "job_id": "ca-7-cci-003883-system-configuration-job" } },
        "aggs": { "max_score": { "max": { "field": "anomaly_score" } } }
      },
      "threat_landscape_risk": {
        "filter": { "term": { "job_id": "ca-7-cci-003883-threat-landscape-job" } },
        "aggs": { "max_score": { "max": { "field": "anomaly_score" } } }
      },
      "personnel_risk": {
        "filter": { "term": { "job_id": "ca-7-cci-003883-personnel-risk-job" } },
        "aggs": { "max_score": { "max": { "field": "anomaly_score" } } }
      },
      "operational_health_risk": {
        "filter": { "term": { "job_id": "ca-7-cci-003883-operational-health-job" } },
        "aggs": { "max_score": { "max": { "field": "anomaly_score" } } }
      },
      "total_risk_score": {
        "bucket_script": {
          "buckets_path": {
            "s1": "system_config_risk > max_score",
            "s2": "threat_landscape_risk > max_score",
            "s3": "personnel_risk > max_score",
            "s4": "operational_health_risk > max_score"
          },
          "script": "(params.s1 ?: 0) + (params.s2 ?: 0) + (params.s3 ?: 0) + (params.s4 ?: 0)"
        }
      }
    }
  },
  "description": "Consolidates all CA-7(4) ML anomalies into a daily risk score per host/entity.",
  "sync": {
    "time": {
      "field": "timestamp",
      "delay": "60s"
    }
  }
}

## 2. How this fulfills CCI-003883

* Woven Integration: It pulls data from the .ml-anomalies-shared index, which is the internal engine where all your jobs store their results. This creates the "core component" for risk monitoring.
* Change Assessment: By using a date_histogram, you can create a line chart in Kibana showing the total_risk_score over time. A spike in this chart is a literal "detection of shifts in security posture" as required by the control.
* Emphasis on Change: If a host has a high system_config_risk AND a high threat_landscape_risk on the same day, the total_risk_score will explode, identifying a high-priority risk event that needs immediate evaluation.

## Implementation Tip
The .ml-anomalies-shared index is a hidden system index. To see the data in it and verify your job IDs are correct, you may need to enable "Include System Indices" in your Kibana settings or Dev Tools.

# Build a Risk Posture Heatmap

To create a Risk Posture Heatmap in Kibana Lens using the data from your new transform index (ca-7-cci-003883-risk-posture-summary), follow these steps.

This visualization will map Time on one axis and Entity (Host/User) on the other, with the Total Risk Score determining the intensity of the color.

## 1. The Kibana Lens Formula

In Lens, once you select the Heatmap visualization type and your transform index, you will use a formula for the Color (Value) field. Since your transform already calculates a total_risk_score, the formula is straightforward, but we use collapse: 'max' to ensure that if there are multiple entries, we see the highest risk peak.

Formula for "Color":

```
max(total_risk_score, kql='total_risk_score > 0')
```

## 2. How to Build the Heatmap

   1. Open Lens: Go to Analytics > Visualize > Create Visualization > Lens.
   2. Select Index: Pick ca-7-cci-003883-risk-posture-summary.
   3. Visualization Type: Select Heatmap from the chart type dropdown.
   4. X-Axis (Horizontal): Drag @timestamp (or timestamp from your transform) here. Set the interval to Daily.
   5. Y-Axis (Vertical): Drag entity_id.keyword (this is the host.name or user.name your transform pivoted on).
   6. Color (Value): Click "Add field" and select Formula. Paste the formula above.
   7. Color Settings:
   * Go to the Display tab.
      * Choose a color palette like "YlOrRd" (Yellow-Orange-Red).
      * Set the Color range to start at 0 and end at your theoretical max (e.g., 400 if you have 4 jobs each capable of scoring 100).
   
## 3. Why this works for CCI-003883

* Identify Shifts: Paragraph (c) requires detecting "shifts in your security posture." A sudden cluster of deep red blocks across multiple entities on a specific day visually alerts you to a widespread "change monitoring" event.
* No Silos: Because this heatmap pulls from your Consolidated Transform, it is the physical realization of risk monitoring being "woven into the broader continuous monitoring program."
* Personnel & Configuration Coverage: If a specific user.name shows a consistent dark red line, you have identified a specific "personnel" risk that requires evaluation.

## Pro-Tip: Adding "Risk Tiers"
If you want to make the heatmap easier to read for auditors, you can use an ifelse formula to categorize the scores into RMF risk levels:

```
ifelse(max(total_risk_score) > 300, 3, ifelse(max(total_risk_score) > 150, 2, 1))
```

This would group your heatmap into 3 distinct color steps: High, Medium, and Low Risk.
