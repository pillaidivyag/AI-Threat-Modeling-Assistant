# AI Threat Model

## Application Description

A customer web portal allows users to log in and view their account information.
The web portal communicates with a REST API. The API accesses a PostgreSQL
database containing customer and transaction data. Support staff use a separate
administrator portal to manage customer accounts. Users access the system over
the internet.

## Assets

### Customer Account Information

**Basis:** Stated

Customer data stored in the PostgreSQL database, including personal details and transaction history.

### User Authentication Endpoint

**Basis:** Stated

API endpoint used by users to log in to the web portal.

### Administrator Portal

**Basis:** Stated

Separate portal used by support staff to manage customer accounts.

### REST API Gateway

**Basis:** Inferred

The interface between the web portal and the PostgreSQL database.

### Database Access Layer

**Basis:** Inferred

Component responsible for retrieving customer and transaction data from PostgreSQL.

### User Session Management

**Basis:** Assumption

Mechanism for maintaining authenticated user sessions during browsing.

## Components

- **Web Portal** (Stated) — Frontend interface for users to view account information.
- **REST API** (Stated) — Backend service that processes user requests and interacts with the database.
- **PostgreSQL Database** (Stated) — Stores customer and transaction data.
- **Administrator Portal** (Stated) — Tool used by support staff to manage customer accounts.

## Trust Boundaries

- **Web Portal to REST API** (Stated) — Boundary between frontend and backend services.
- **REST API to PostgreSQL Database** (Stated) — Boundary between application logic and data storage.
- **Administrator Portal to Database** (Inferred) — Boundary between admin tools and customer data storage.

## Data Flows

| Source | Destination | Data | Basis |
|---|---|---|---|
| Web Portal | REST API | User login credentials and session tokens | Stated |
| REST API | PostgreSQL Database | Customer account and transaction data | Stated |
| Administrator Portal | PostgreSQL Database | Account management operations | Inferred |

## Threat Summary

| ID | STRIDE | Basis | Likelihood | Impact | Score | Risk | Element |
|---|---|---|---|---|---:|---|---|
| STRIDE-Auth-01 | Spoofing | Stated | Medium | High | 6 | High | User Authentication Endpoint |
| STRIDE-Auth-02 | Spoofing | Assumption | Medium | High | 6 | High | User Session Management |
| STRIDE-Priv-01 | Spoofing | Stated | Low | High | 3 | Medium | Administrator Portal |
| STRIDE-Priv-02 | Elevation of Privilege | Stated | Medium | High | 6 | High | REST API to PostgreSQL Database |
| STRIDE-Data-01 | Information Disclosure | Stated | Medium | High | 6 | High | Customer Account Information |
| STRIDE-Avail-01 | Denial of Service | Inferred | Low | Medium | 2 | Low | REST API |

## Threat Details

### STRIDE-Auth-01 — Spoofing

**Basis:** Stated

**Affected Element:** User Authentication Endpoint

**Scenario:** An attacker could intercept or manipulate login credentials during transmission, leading to unauthorized access to customer accounts if authentication is not performed over secure channels.

**Rationale:** Authentication is required for access, but no mention of secure transport (e.g., HTTPS).

**Mitigation:** Enforce TLS 1.2+ for all communication between the web portal and the REST API.

**Likelihood:** Medium

**Impact:** High

**Risk:** High (Score: 6)

### STRIDE-Auth-02 — Spoofing

**Basis:** Assumption

**Affected Element:** User Session Management

**Scenario:** An attacker could obtain a valid session token through cross-site scripting (XSS) and reuse it to access another user's account if session tokens are not properly scoped or invalidated.

**Rationale:** Session tokens are not described, but session management is a common attack surface in web applications.

**Mitigation:** Implement secure session tokens with short expiration times and include a secure, non-reusable refresh token mechanism.

**Likelihood:** Medium

**Impact:** High

**Risk:** High (Score: 6)

### STRIDE-Priv-01 — Spoofing

**Basis:** Stated

**Affected Element:** Administrator Portal

**Scenario:** An attacker with access to the administrator portal could manipulate account data or disable user access if authentication or authorisation is not strictly enforced.

**Rationale:** Administrator portal has elevated privileges, but no details on access controls are provided.

**Mitigation:** Enforce multi-factor authentication (MFA) and role-based access control (RBAC) for the administrator portal.

**Likelihood:** Low

**Impact:** High

**Risk:** Medium (Score: 3)

### STRIDE-Priv-02 — Elevation of Privilege

**Basis:** Stated

**Affected Element:** REST API to PostgreSQL Database

**Scenario:** An attacker who gains access to the REST API could exploit a vulnerability in the database query layer to execute arbitrary SQL commands, leading to data exposure or modification.

**Rationale:** The API accesses a database directly, and no input validation is mentioned.

**Mitigation:** Implement parameterised queries and validate all inputs to prevent SQL injection.

**Likelihood:** Medium

**Impact:** High

**Risk:** High (Score: 6)

### STRIDE-Data-01 — Information Disclosure

**Basis:** Stated

**Affected Element:** Customer Account Information

**Scenario:** An attacker could access customer transaction data through a misconfigured API endpoint or error message, exposing sensitive financial information.

**Rationale:** Customer data is stored in the database and exposed via API responses.

**Mitigation:** Implement strict response headers, avoid exposing error details, and apply data minimisation principles.

**Likelihood:** Medium

**Impact:** High

**Risk:** High (Score: 6)

### STRIDE-Avail-01 — Denial of Service

**Basis:** Inferred

**Affected Element:** REST API

**Scenario:** An attacker could send a large number of requests to the API to exhaust server resources, causing service degradation or unavailability for legitimate users.

**Rationale:** The API is exposed to the internet and handles user requests, making it a potential target for DDoS attacks.

**Mitigation:** Implement rate limiting and use a web application firewall (WAF) to detect and block abnormal traffic patterns.

**Likelihood:** Low

**Impact:** Medium

**Risk:** Low (Score: 2)

## Security Questions

- Is the administrator portal accessible only to authenticated support staff with verified identities?
- Are all API endpoints properly documented and protected with access controls?
- Is input validation enforced on all API endpoints, especially those retrieving or modifying customer data?
- Are session tokens stored securely and transmitted over encrypted channels?
- Is the PostgreSQL database configured with proper access controls and audit logging?
- Are error messages returned to users sanitized to avoid revealing internal system details?

## Assumptions

- Session management is implemented in the web portal.
- The REST API does not perform input validation on all request parameters.
- The administrator portal has no built-in audit trail or access logging.
- The web portal does not implement content security policies (CSP) or XSS protections.

## Risk Calculation

Risk is calculated by the Python application using a deterministic 3x3 likelihood and impact matrix.

| Score | Risk |
|---:|---|
| 1–2 | Low |
| 3–4 | Medium |
| 5–6 | High |
| 7–9 | Critical |

The AI provides likelihood and impact. The application calculates the final risk score and risk rating.

## AI Security Considerations

The application description is treated as untrusted input. Instructions contained within the submitted description are not treated as system instructions.

The AI output is validated before it is accepted. Required fields, STRIDE categories, evidence classifications, likelihood, impact, and threat identifiers are checked.

## Review Note

This tool provides AI-assisted threat modelling and does not replace security architecture review. Generated threats, assumptions, security questions, and mitigations should be validated against the actual architecture, business context, data classification, security requirements, and organisational controls.
