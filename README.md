![SecureMail](https://github.com/user-attachments/assets/24ecc351-7873-45a6-8c4c-4d56cd88d7d7)

## Project Overview
SecureMail integrates advanced **ML models** including **NLP techniques** and security best practices to detect phishing emails efficiently. It follows a **secure software development lifecycle (SDLC)**, implementing security measures in all phases: **development, CI/CD, and production**.

---

<details>
  <summary>Table of contents</summary>
 
-  <kbd> [Available Languages](#available-languages)</kbd>
-  <kbd> [Project Overview](#project-overview)</kbd>
-  <kbd> [Development Phase](#development-phase)</kbd>
-  <kbd> [CI/CD Phase](#cicd-phase)</kbd>
-  <kbd> [Production Phase](#production-phase)</kbd>
-  <kbd> [Design and Architecture](#design-and-architecture)</kbd>
-  <kbd> [Future Enhancements](#future-enhancements)</kbd>
-  <kbd> [License](#license)</kbd>

</details>

---

<details>
  <summary>Available Languages</summary>

-  <kbd> [Español](README.es.md)</kbd>
-  <kbd> [Português](README.pt.md)</kbd>

</details>

---

## Development Phase

### Secure Coding Practices:
- **Data Sanitization**:
  - External inputs (user-supplied data) validated using **Pydantic**.
  - Internal inputs (third-party API responses) reviewed for anomalies.
- **Environment Variable Management**:
  - Sensitive information (e.g., API keys) managed using **Python-dotenv**.
- **Threat Mitigation Strategies**:
  - Implementing OWASP-recommended secure coding guidelines.

---

## CI/CD Phase

### Security Tools and Testing:
- **Pylint**: Enforces code quality and security best practices.
- **Pytest**: Ensures API response accuracy through rigorous testing.
- **Snyk**: Conducts static security analysis (SAST + SCA) to detect vulnerabilities.
- **Docker Bench Security**: Assesses Docker container security configurations.
- **OWASP ZAP**: Conduct Dynamic Applicaction Security Testing (DAST)


---

## Production Phase

### Security & Monitoring:
- **Continuous Security Scanning**:
  - **Snyk** for dependency vulnerability detection in production.
  - **Docker Bench Security** for runtime container security evaluations.
  - **OWASP ZAP** for dynamic testing.
- **Deployment Platform**:
  - Hosted on **Render (PaaS)** using Docker-based deployment for reliability.

> [!IMPORTANT]  
> Always ensure continuous monitoring to catch any new vulnerabilities as they arise in the production environment.

---

## Design and Architecture

### Data Flow Architecture:
SecureMail follows a **structured data processing pipeline** to analyze emails. Below is an overview of the data flow:
![dataflow](./images/dataflow.png)


- **Code Signing with GPG key**:
  - Uses GnuPG to enhance Code Signing security within Github Commits.

> [!WARNING] 
> If you do not properly secure your code signing process, you risk introducing malicious code into your software eg: SolarWinds.

---

## Future Enhancements

- **Integrating Application Security Orchestration and Correlation (ASOC)**.
- **Advanced Threat Modeling**:
  - Using **OWASP Threat Dragon** for structured threat analysis.


---

## License
Distributed under the **GPL-3.0** license. See the [LICENSE](./LICENSE) file for more details.
