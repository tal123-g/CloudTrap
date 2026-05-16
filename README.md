# CloudTrap: A Multi-Cloud Honeypot Deception Network

CloudTrap is a multi-cloud honeypot deception network deployed across AWS and GCP to capture and analyze real-world attacker behavior targeting cloud infrastructure.

## Features
- Fake REST API honeypot
- Fake S3-compatible honeypot
- Fake login portal
- Centralized logging (AWS CloudWatch + GCP Logging)
- PostgreSQL event storage
- Real-time dashboard
- Cross-cloud log forwarding
- Dockerized deployment
- CI/CD pipeline using GitHub Actions

## Technologies Used
- AWS EC2
- Google Compute Engine
- Docker & Docker Compose
- Flask
- PostgreSQL
- CloudWatch Logs
- GCP Cloud Logging
- GitHub Actions

## Deployment
AWS hosts:
- API Honeypot
- S3 Honeypot
- Analyzer
- Dashboard
- PostgreSQL

GCP hosts:
- Login Portal
- Log Forwarder

## Authors
Tala Ghosheh  
Katrin Zagha
