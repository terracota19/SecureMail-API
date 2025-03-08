![SecureMail](https://github.com/user-attachments/assets/24ecc351-7873-45a6-8c4c-4d56cd88d7d7)

## Visión General del Proyecto
SecureMail integra modelos avanzados de **ML** que incluyen **técnicas de PNL** y mejores prácticas de seguridad para detectar correos electrónicos de phishing de manera eficiente. Sigue un **ciclo de vida seguro de desarrollo de software (SDLC)**, implementando medidas de seguridad en todas las fases: **desarrollo, CI/CD y producción**.

---

## Tabla de Contenidos
- [Idiomas Disponibles](#idiomas-disponibles)
- [Visión General del Proyecto](#visión-general-del-proyecto)
- [Fase de Desarrollo](#fase-de-desarrollo)
- [Fase de CI/CD](#fase-de-cicd)
- [Fase de Producción](#fase-de-producción)
- [Diseño y Arquitectura](#diseño-y-arquitectura)
- [Mejoras Futuras](#mejoras-futuras)
- [Licencia](#licencia)

---

## Idiomas Disponibles
- [Español](README.es.md)
- [Português](README.pt.md)

---

## Fase de Desarrollo

### Prácticas de Codificación Segura:
- **Sanitización de Datos**:
  - Las entradas externas (datos proporcionados por el usuario) son validadas utilizando **Pydantic**.
  - Las entradas internas (respuestas de API de terceros) son revisadas para detectar anomalías.
- **Gestión de Variables de Entorno**:
  - Información sensible (por ejemplo, claves de API) gestionada usando **Python-dotenv**.
- **Estrategias de Mitigación de Amenazas**:
  - Implementación de las directrices de codificación segura recomendadas por OWASP.

---

## Fase de CI/CD

### Herramientas de Seguridad y Pruebas:
- **Pylint**: Aplica las mejores prácticas de calidad de código y seguridad.
- **Pytest**: Asegura la precisión de las respuestas de la API mediante pruebas rigurosas.
- **Snyk**: Realiza análisis de seguridad estática (SAST + SCA) para detectar vulnerabilidades.
- **Docker Bench Security**: Evalúa las configuraciones de seguridad de los contenedores Docker.
- **OWASP ZAP**: Realiza pruebas de seguridad de aplicaciones dinámicas (DAST).

---

## Fase de Producción

### Seguridad y Monitoreo:
- **Escaneo Continuo de Seguridad**:
  - **Snyk** para detectar vulnerabilidades de dependencias en producción.
  - **Docker Bench Security** para evaluaciones de seguridad en tiempo de ejecución de contenedores.
  - **OWASP ZAP** para pruebas dinámicas.
- **Plataforma de Despliegue**:
  - Alojado en **Render (PaaS)** usando despliegue basado en Docker para mayor fiabilidad.

> [!IMPORTANTE]  
> Asegúrate siempre de monitorear de forma continua para detectar cualquier nueva vulnerabilidad a medida que surja en el entorno de producción.

---

## Diseño y Arquitectura

### Arquitectura del Flujo de Datos:
SecureMail sigue una **tubería estructurada de procesamiento de datos** para analizar los correos electrónicos. A continuación se muestra una visión general del flujo de datos:
![dataflow](./images/dataflow.png)

- **Firma de Código con Clave GPG**:
  - Usa GnuPG para mejorar la seguridad de la firma de código dentro de los commits de Github.

> [!ADVERTENCIA]  
> Si no aseguras adecuadamente tu proceso de firma de código, corres el riesgo de introducir código malicioso en tu software, por ejemplo: SolarWinds.

---

## Mejoras Futuras

- **Integración de Orquestación y Correlación de Seguridad de Aplicaciones (ASOC)**.
- **Modelado Avanzado de Amenazas**:
  - Usando **OWASP Threat Dragon** para un análisis estructurado de amenazas.

---

## Licencia
Distribuido bajo la licencia **GPL-3.0**. Consulta el archivo [LICENSE](./LICENSE) para más detalles.
