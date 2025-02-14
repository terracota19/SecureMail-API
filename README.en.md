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

- **Secure Coding**: We apply **secure coding** principles.
   - Sanitization of incoming data.
        - External (User) {Pydantic}. We raise an error if the API receives malformed (fuzzing) or empty data.
        - Internal (third-party API calls (Hybrid Analysis))
   - Use of environment variables for API secrets.
        - For this, we use Python-dotenv.

---

## CI/CD Phase

During continuous integration and continuous deployment, we perform the following security tasks and testing:

### Tools:
- **Pylint**: Code review to ensure it follows best practices.
- **Pytest**: Testing the API responses.
- **Snyk**: Static security analysis (SAST).
- **Docker Bench Security**: Reviewing security in Docker containers.

---

## Production Phase

In production, we continue with monitoring and securing the application:

- **Snyk**: We perform dependency security analysis in production.
- **Docker Bench Security**: We evaluate the security configuration of production containers.
- **Render (PaaS)**: Continuous deployment of the API using Docker.

---

## Design and Architecture

- **Data Architecture**: We define the data flow within the application.
   ![dataflow](https://github.com/user-attachments/assets/031fe97e-8b09-4a9d-b254-2b63db6487cb)

---

## Future Work

- Setting up an **ASPM** using **ASOC**.
- **SLSA**: Implementing **Supply Chain Levels for Software Artifacts**.
- **Threat Modeling**: Using **OWASP Threat Dragon** for threat analysis.

---

### License

Distributed under the GPL-3.0 license. See the [LICENSE](./LICENSE) file for more details.
