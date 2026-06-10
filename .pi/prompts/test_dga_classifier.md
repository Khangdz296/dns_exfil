# DGA Classifier Agent - Test Prompt

You are the **dga_classifier_agent** running in Stage 2 of the DNS
exfiltration pipeline.

## Your Task

Take the normalized DNS queries from the Stage 1 output and score every query
for DGA likelihood using the `score_dga` tool.

## Test Input Data

Read the normalized DNS queries from:

```text
data/output/dns_queries.json
```

The file contains a JSON array. Each query follows this structure:

```json
{
  "query_id": 1,
  "timestamp": 0.0,
  "src_ip": "10.0.0.1",
  "domain": "example.com",
  "query_type": "A",
  "subdomain": "example",
  "tld": "com",
  "label_count": 2,
  "domain_length": 11,
  "digit_ratio": 0.0,
  "count": 1,
  "source": "pcap"
}
```

## Instructions

1. Load all DNS queries from `data/output/dns_queries.json`.
2. Pass the complete list directly to the `score_dga` tool from the
   `dga_classifier` skill.
3. The tool will:
   - Extract these 7 features: `domain_length`, `digit_ratio`, `label_count`,
     `subdomain_length`, `vowel_ratio`, `consonant_ratio`, and
     `unique_char_ratio`.
   - Load the pre-trained Random Forest model from `models/dga_model.pkl`.
   - Compute the DGA probability for every domain.
   - Return a deep copy of the input list with a `dga_score` field added to
     every record.
4. Split the scored records into:
   - Records where `dga_score > 0.5`.
   - Records where `dga_score < 0.5`.
5. Return a concise summary instead of printing the complete scored list:
   - Total number of scored queries.
   - Number of records in each score group.
   - Up to 5 example records from each score group.
   - Every example must contain `query_id`, `domain`, and `dga_score`.
6. Count records where `dga_score == 0.5` separately. Do not include those
   records in either score group.
7. Use actual classifier results. Do not invent, estimate, or hard-code scores.

## Expected Output

Return valid JSON with this structure:

```json
{
  "total_scored": 100,
  "dga_score_above_0_5": {
    "count": 60,
    "examples": [
      {
        "query_id": 1,
        "domain": "random-looking-domain.example",
        "dga_score": 0.87
      }
    ]
  },
  "dga_score_below_0_5": {
    "count": 40,
    "examples": [
      {
        "query_id": 2,
        "domain": "normal-domain.example",
        "dga_score": 0.12
      }
    ]
  },
  "dga_score_equal_0_5": {
    "count": 0
  }
}
```

The values above are illustrative. Include several examples in both
`examples` arrays when records are available, with a maximum of 5 examples
per group.

**Start processing the test data now.**
