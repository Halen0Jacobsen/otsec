## Project Overview

The Secure OT Asset and Telemetry Platform is a security-focused software engineering project intended to demonstrate the design, development, verification, and documentation of a secure platform for managing operational technology and IoT assets.

The system will provide centralized asset management, device authentication, telemetry ingestion, security monitoring, audit logging, role-based access control, and security alerting. Initial field devices will be represented through Python-based simulators, allowing the system architecture and security controls to be developed and tested before integration with physical OT and embedded devices.

The project will use a Secure Software Development Lifecycle rather than beginning directly with implementation. Development will progress through requirements engineering, architecture and security design, threat modeling, verification planning, secure implementation, security testing, remediation, and release assurance.

The targeted project completion date is March 2027, with approximately one dedicated project workday per week.

## Project Purpose

The primary purpose of the project is to develop practical experience applying software security and cybersecurity engineering principles throughout the complete lifecycle of a realistic OT-oriented system.

The project is intended to demonstrate competence across several related disciplines:

- Secure software development
- Java and Spring Boot development
- Application security
- Identity and access management
- Device identity and authentication
- Secure API development
- MQTT and HTTP communications
- OT and IoT security architecture
- Threat modeling
- Security monitoring and auditability
- DevSecOps
- Software supply-chain security
- Security testing and remediation

The final result should demonstrate not only that the application functions correctly, but that security requirements can be traced from initial requirements through architecture, implementation, verification, and final release.

## System Concept

The platform will manage OT and IoT devices such as:

- Pump controllers
- Irrigation controllers
- Environmental sensors
- Weather stations
- Energy meters
- PLCs and industrial gateways

Python simulators will initially represent these devices. Physical ESP32, STM32, Arduino Portenta, PLC, RTU, and other embedded devices may later replace or supplement the simulators without requiring major changes to the backend architecture.

The planned high-level architecture consists of:

- Java Spring Boot application backend
- PostgreSQL database
- Keycloak identity provider
- Eclipse Mosquitto MQTT broker
- Python-based device simulators
- HTTPS REST interfaces
- MQTT telemetry interfaces
- Web-based management and monitoring interface

HTTP and MQTT telemetry sources will converge on a common internal telemetry-processing service so that transport mechanisms remain separated from application-level processing logic.

## Core Capabilities

The initial platform will provide:

### Asset Management

Register, view, modify, and manage OT and IoT assets and their associated metadata.

### User Identity and Access Management

Authenticate users through OAuth 2.0 and OpenID Connect and enforce role-based access controls for system operations.

### Device Identity

Assign devices unique identities and credentials and reject telemetry from unauthorized or unknown devices.

### Telemetry Ingestion

Receive telemetry through HTTPS and MQTT interfaces.

### Telemetry Processing

Validate, normalize, store, and associate telemetry with registered assets.

### Security Monitoring

Generate security events for conditions such as authentication failures, authorization failures, invalid telemetry, configuration changes, and abnormal device activity.

### Audit Logging

Maintain security-relevant records of administrative and configuration activities.

### Security Alerting

Generate alerts based on device state, authentication behavior, telemetry conditions, and other defined security rules.

### Secure Development Pipeline

Integrate automated security controls such as static analysis, dependency analysis, SBOM generation, container scanning, automated testing, and security verification into the software delivery process.

## Secure SDLC Approach

The project will progress through the following lifecycle phases:

1. Project initiation and scope definition
2. Functional and security requirements engineering
3. Non-functional and OT requirements engineering
4. System architecture
5. Security architecture
6. Threat modeling
7. Detailed component design
8. Security verification planning
9. Secure implementation
10. Automated security analysis
11. Security verification and negative testing
12. Vulnerability remediation
13. Final security assurance and release

Each phase will produce documented artifacts and defined exit criteria before progression to the next major phase.

Security requirements will be assigned identifiers and tracked through a requirements traceability matrix connecting requirements to architecture decisions, implementation components, verification procedures, and final test results.

## Security Engineering Objectives

The project will explicitly address:

- Authentication
- Authorization
- Least privilege
- Device identity
- Input validation
- Secure communications
- Secrets management
- Auditability
- Security monitoring
- Attack-surface reduction
- Dependency security
- Software supply-chain security
- Secure configuration
- Network segmentation concepts
- Availability considerations

The project's initial security design includes OAuth2/OIDC/JWT authentication, role-based authorization, device credentials, TLS, validation controls, secure secrets management, and security-focused audit logging.

## Threat Modeling

Threat modeling will be conducted before major implementation work.

STRIDE will be used as an initial threat-modeling methodology to evaluate:

- Spoofing
- Tampering
- Repudiation
- Information disclosure
- Denial of service
- Elevation of privilege

Threats will be associated with affected components, trust boundaries, security requirements, mitigating controls, verification procedures, and residual risk.