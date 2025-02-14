# SecureMail: API para la Detección de Phishing con Machine Learning

**SecureMail** es una API que utiliza técnicas de **Machine Learning (ML)** para evaluar si un correo electrónico es un intento de **phishing**. Esta API realiza análisis de seguridad y proporciona predicciones sobre correos electrónicos sospechosos.

---

## Índice
- [Fase de Desarrollo](#fase-de-desarrollo)
- [Fase de CI/CD](#fase-de-cicd)
- [Fase de Producción](#fase-de-producción)
- [Diseño y Arquitectura](#diseño-y-arquitectura)
- [Trabajo Futuro](#trabajo-futuro)

---

## Fase de Desarrollo

- **Secure Coding**: Aplicamos principios de **código seguro**. Sanetizacion de entradas de usuarios {Pydantic} e internas (llamadas a APIs de tercero (Hybrid Analysis)).

---

## Fase de CI/CD

Durante la integración continua y despliegue continuo, realizamos las siguientes tareas de seguridad y pruebas:

### Herramientas:
- **Pylint**: Revisión del código para asegurar que cumple con las mejores prácticas.
- **Pytest**: Testeo de las respuestas de la API.
- **Snyk**: Análisis de seguridad estático (SAST).
- **Docker Bench Security**: Revisión de la seguridad en los contenedores Docker.

---

## Fase de Producción

En producción, seguimos con el monitoreo y aseguramos la aplicación:

- **Snyk**: Realizamos análisis de seguridad de dependencias en producción.
- **Docker Bench Security**: Evaluamos la configuración de seguridad en los contenedores de producción.
- **Render (PaaS)**: Despliegue continuo de la API mediante Docker.

---

## Diseño y Arquitectura

- **Arquitectura de Datos**: Definimos el flujo de datos dentro de la aplicación para minimizar riesgos.
   ![dataflow](https://github.com/user-attachments/assets/031fe97e-8b09-4a9d-b254-2b63db6487cb)


---

## Trabajo Futuro

- Configuración de un **ASPM** utilizando **ASOC**.
- **SLSA**: Implementación de **Supply Chain Levels for Software Artifacts**.
- **Modelado de Amenazas**: **OWASP Threat Dragon** para realizar un análisis de amenazas.

---

### Licencia

Distribuido bajo la licencia GPL-3.0 . Ver el archivo [LICENSE](./LICENSE) para más detalles.
