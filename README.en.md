
# SecureMail: Phishing Detection API with Machine Learning

**SecureMail** is an API that uses **Machine Learning (ML)** techniques to assess whether an email is a phishing attempt. This API performs security analysis and provides predictions about suspicious emails.

---

## Table of Contents
- [Development Phase](#development-phase)
- [CI/CD Phase](#cicd-phase)
- [Production Phase](#production-phase)
- [Design and Architecture](#design-and-architecture)
- [Future Work](#future-work)

---

## Development Phase

- **Secure Coding**: We apply **secure coding** principles. Sanitization of user inputs {Pydantic} and internal inputs (third-party API calls like Hybrid Analysis).

---

## CI/CD Phase

During the continuous integration and continuous deployment process, we perform the following security tasks and tests:

### Tools:
- **Pylint**: Code review to ensure adherence to best practices.
- **Pytest**: Testing API responses.
- **Snyk**: Static Application Security Testing (SAST).
- **Docker Bench Security**: Security review of Docker containers.

---

## Production Phase

In production, we continue with monitoring and securing the application:

- **Snyk**: Security analysis of dependencies in production.
- **Docker Bench Security**: We assess the security configuration of production containers.
- **Render (PaaS)**: Continuous deployment of the API via Docker.

---

## Design and Architecture

- **Data Architecture**: We define the data flow within the application.
   ![dataflow](https://github.com/user-attachments/assets/031fe97e-8b09-4a9d-b254-2b63db6487cb)

---

## Future Work

- Set up an **ASPM** using **ASOC**.
- **SLSA**: Implement **Supply Chain Levels for Software Artifacts**.
- **Threat Modeling**: **OWASP Threat Dragon** for threat analysis.

---

### License

Distributed under the GPL-3.0 license. See the [LICENSE](./LICENSE) file for more details.
