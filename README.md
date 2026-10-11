
# SentinelX

SentinelX is a modular cybersecurity project designed to
explore static file analysis, threat indicators, and
explainable security reporting.

## Current Features

- SHA-256 file fingerprinting
- File size and metadata reporting
- Basic static indicator scanning
- JSON security reports
- Automated tests

## Technology Stack

- Python 3
- Standard Python libraries
- JSON
- unittest
- Git and GitHub

## Run Locally

```bash
python3 sentinelx.py samples/demo.txt
```

## Run Tests

```bash
python3 -m unittest discover -s tests -v
```

## Safety and Limitations

SentinelX does not execute analyzed files.
Indicator matches are not proof of malware.
This prototype is intended for educational use.

## Roadmap

- Structured logging and error handling
- SQLite analysis history
- Explainable machine-learning experiments
- FastAPI service
- Security dashboard
- Optional cloud deployment with access controls
