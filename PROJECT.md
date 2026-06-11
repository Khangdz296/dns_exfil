# Project

## Title

DNS Exfiltration Detector

## Objective

Detect DNS exfiltration attempts from:

- PCAP files
- Live DNS traffic

## Pipeline

### Stage 1

- PCAP Reader Agent
- DNS Extractor Agent

### Stage 2 (Parallel)

- Entropy Analysis Agent
- DGA Classification Agent
- Embedding Similarity Agent

All three agents process the same DNS query list concurrently.

### Stage 3

- Aggregator Agent
- GPT Report Agent

## Requirements

- Python implementation
- Multi-agent architecture
- Minimum 3 sequential stages
- At least one parallel stage
- Modular folder structure
- Easy work division for 3 students
- Suitable for Network Programming + AI/ML course

## Recommended Technologies

- Python
- Scapy
- PyShark
- asyncio
- concurrent.futures
- pandas
- numpy
- scikit-learn
- transformers
- sentence-transformers
- joblib

## Expected Output

- Risk score
- Suspicious domains
- AI-generated security report
- Execution logs
- JSON intermediate results
