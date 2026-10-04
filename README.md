# AI Threat Modelling Assistant

A local AI-assisted threat modelling tool that analyses an application description, identifies security threats using the STRIDE methodology, and produces structured security recommendations.

The project demonstrates how generative AI can support security architecture and threat modelling while keeping the security analysis structured, reviewable and human-controlled.

## What It Does

The tool takes a plain-language description of an application and generates:

* Key application assets and components
* Trust boundaries and relevant data flows
* STRIDE-based threats
* Threat severity and rationale
* Recommended security controls and mitigations
* Assumptions and areas requiring security review

The analysis is generated locally using an open-source large language model through Ollama.

## Security Focus

The assistant is designed around common security architecture activities:

* Threat identification
* STRIDE threat modelling
* Attack-path reasoning
* Security control recommendations
* Risk-based prioritisation
* Secure-by-design review

The tool is intended to support, not replace, security review by a qualified analyst or architect.

## Architecture

```text
                    ┌──────────────────────────┐
                    │    Application Input     │
                    │  Architecture / Use Case │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │   Python Threat Modeler  │
                    │                          │
                    │ Prompt + Validation      │
                    │ STRIDE Instructions      │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │         Ollama            │
                    │      Local LLM           │
                    │        qwen3:8b            │
                    └────────────┬─────────────┘
                                 │
                                 ▼
                    ┌──────────────────────────┐
                    │   Structured Threat      │
                    │        Analysis           │
                    │                          │
                    │ Assets                   │
                    │ Threats                  │
                    │ Risk                     │
                    │ Mitigations              │
                    │ Assumptions              │
                    └──────────────────────────┘
```

## STRIDE Coverage

The threat model evaluates the application against the six STRIDE categories:

| Category               | Security Concern                               |
| ---------------------- | ---------------------------------------------- |
| Spoofing               | Impersonating a user, service or component     |
| Tampering              | Unauthorised modification of data or processes |
| Repudiation            | Inability to reliably trace or prove an action |
| Information Disclosure | Unauthorised exposure of sensitive information |
| Denial of Service      | Loss of availability or service degradation    |
| Elevation of Privilege | Gaining permissions beyond those authorised    |

## Technology

* Python
* Ollama
* Qwen3 8B
* REST API communication with the local Ollama service
* VS Code
* Git / GitHub

## Project Structure

```text
AI-Threat-Modeling-Assistant/
│
├── src/
│   └── threat_modeler.py
├── examples/
│   └── sample_application.txt
├── screenshots/
├── tests/
├── README.md
├── .gitignore
└── requirements.txt
```

## Running the Application

Start the local Ollama service and ensure the Qwen3 model is available.

From the project directory:

```powershell
.venv\Scripts\activate
python src\threat_modeler.py
```

Enter an application architecture or system description when prompted.

The tool sends the description to the locally running LLM and presents a structured threat model.

## Example Use Case

Example application:

```text
A customer web portal allows users to log in, view account information
and submit transactions. The web application communicates with a REST API.
The API accesses a PostgreSQL database containing customer and transaction
data. An administrator portal is used by support staff.
```

The assistant analyses the system and identifies relevant threats across the application's components and data flows.

## Security Design Principles

The project applies several secure-by-design principles:

* Least privilege
* Strong authentication and authorisation
* Encryption in transit
* Protection of sensitive data
* Input validation
* Secure logging and monitoring
* Network segmentation
* Secure service-to-service communication
* Administrative access controls

## Limitations

AI-generated threat models can contain incorrect assumptions, omissions or overly generic recommendations.

The output therefore includes assumptions and should be validated against the actual architecture, business requirements, data classification, threat landscape and organisational security standards.

## Portfolio Demonstration

The project demonstrates practical experience across:

**Security Operations → Threat Analysis → Threat Modelling → Security Architecture → Secure-by-Design**

It combines hands-on implementation with established security methodology rather than treating AI security as a purely theoretical topic.
