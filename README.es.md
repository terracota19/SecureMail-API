```
   _____                          __  __       _ _ 
  / ____|                        |  \/  |     (_) |
 | (___   ___  ___ _   _ _ __ ___| \  / | __ _ _| |
  \___ \ / _ \/ __| | | | '__/ _ \ |\/| |/ _` | | |
  ____) |  __/ (__| |_| | | |  __/ |  | | (_| | | |
 |_____/ \___|\___|\__,_|_|  \___|_|  |_|\__,_|_|_|
                                                   
```

---

## Descripción del Proyecto
SecureMail integra avanzados **modelos de ML** y mejores prácticas de seguridad para detectar correos electrónicos de phishing de manera eficiente. Sigue un **ciclo de vida de desarrollo de software seguro (SDLC)**, implementando medidas de seguridad en todas las fases: **desarrollo, CI/CD y producción**.

---

## Tabla de Contenidos
- [Idiomas Disponibles](#idiomas-disponibles)
- [Descripción del Proyecto](#descripción-del-proyecto)
- [Fase de Desarrollo](#fase-de-desarrollo)
- [Fase CI/CD](#fase-cicd)
- [Fase de Producción](#fase-de-producción)
- [Diseño y Arquitectura](#diseño-y-arquitectura)
- [Mejoras Futuras](#mejoras-futuras)
- [Licencia](#licencia)

---

## Idiomas Disponibles
- [Español](README.es.md)
- [Português](README.pt.md)

## Fase de Desarrollo

### Prácticas de Codificación Segura:
- **Sanitización de Datos**:
  - Entradas externas (datos proporcionados por el usuario) validadas utilizando **Pydantic**.
  - Entradas internas (respuestas de API de terceros) revisadas en busca de anomalías.
- **Gestión de Variables de Entorno**:
  - Información sensible (por ejemplo, claves de API) gestionada usando **Python-dotenv**.
- **Estrategias de Mitigación de Amenazas**:
  - Implementación de las directrices de codificación segura recomendadas por OWASP.

---

## Fase CI/CD

### Herramientas de Seguridad y Pruebas:
- **Pylint**: Garantiza la calidad del código y las mejores prácticas de seguridad.
- **Pytest**: Asegura la precisión de la respuesta de la API mediante rigurosas pruebas.
- **Snyk**: Realiza análisis de seguridad estática (SAST) para detectar vulnerabilidades.
- **Docker Bench Security**: Evalúa la configuración de seguridad de los contenedores Docker.

---

## Fase de Producción

### Seguridad y Monitoreo:
- **Escaneo Continuo de Seguridad**:
  - **Snyk** para detectar vulnerabilidades en las dependencias en producción.
  - **Docker Bench Security** para evaluaciones de seguridad de contenedores en tiempo de ejecución.
- **Plataforma de Despliegue**:
  - Alojado en **Render (PaaS)** utilizando despliegue basado en Docker para fiabilidad.

---

## Diseño y Arquitectura

- **Arquitectura del Flujo de Datos**:
  - SecureMail sigue una **tubería de procesamiento de datos estructurada** para analizar los correos electrónicos.
  - A continuación se muestra una visión general del flujo de datos:
  
    ![dataflow](https://github.com/user-attachments/assets/031fe97e-8b09-4a9d-b254-2b63db6487cb)

---

## Mejoras Futuras

- **Gestión de Postura de Seguridad de la Aplicación (ASPM)**:
  - Integración de **Orquestación y Correlación de Seguridad de Aplicaciones (ASOC)**.
- **Seguridad de la Cadena de Suministro de Software**:
  - Implementación de **SLSA (Niveles de la Cadena de Suministro para Artefactos de Software)**.
- **Modelado de Amenazas Avanzado**:
  - Uso de **OWASP Threat Dragon** para un análisis estructurado de amenazas.

---

## Licencia
Distribuido bajo la licencia **GPL-3.0**. Consulta el archivo [LICENSE](./LICENSE) para más detalles.
