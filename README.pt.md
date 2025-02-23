```
   _____                          __  __       _ _ 
  / ____|                        |  \/  |     (_) |
 | (___   ___  ___ _   _ _ __ ___| \  / | __ _ _| |
  \___ \ / _ \/ __| | | | '__/ _ \ |\/| |/ _` | | |
  ____) |  __/ (__| |_| | | |  __/ |  | | (_| | | |
 |_____/ \___|\___|\__,_|_|  \___|_|  |_|\__,_|_|_|
                                                   
```

---

## Descrição do Projeto
SecureMail integra **modelos de ML** avançados e melhores práticas de segurança para detectar e-mails de phishing de maneira eficiente. Segue um **ciclo de vida de desenvolvimento de software seguro (SDLC)**, implementando medidas de segurança em todas as fases: **desenvolvimento, CI/CD e produção**.

---

## Índice
- [Idiomas Disponíveis](#idiomas-disponíveis)
- [Descrição do Projeto](#descrição-do-projeto)
- [Fase de Desenvolvimento](#fase-de-desenvolvimento)
- [Fase CI/CD](#fase-cicd)
- [Fase de Produção](#fase-de-produção)
- [Design e Arquitetura](#design-e-arquitetura)
- [Melhorias Futuras](#melhorias-futuras)
- [Licença](#licença)

---

## Idiomas Disponíveis
- [Español](README.es.md)
- [Português](README.pt.md)

## Fase de Desenvolvimento

### Práticas de Codificação Segura:
- **Sanitização de Dados**:
  - Entradas externas (dados fornecidos pelo usuário) validadas usando **Pydantic**.
  - Entradas internas (respostas de API de terceiros) revisadas para anomalias.
- **Gestão de Variáveis de Ambiente**:
  - Informações sensíveis (como chaves de API) gerenciadas com **Python-dotenv**.
- **Estratégias de Mitigação de Ameaças**:
  - Implementação de diretrizes de codificação segura recomendadas pelo OWASP.

---

## Fase CI/CD

### Ferramentas de Segurança e Testes:
- **Pylint**: Aplica melhores práticas de segurança e qualidade de código.
- **Pytest**: Garante precisão na resposta da API através de testes rigorosos.
- **Snyk**: Realiza análise de segurança estática (SAST) para detectar vulnerabilidades.
- **Docker Bench Security**: Avalia as configurações de segurança de contêineres Docker.

---

## Fase de Produção

### Segurança e Monitoramento:
- **Escaneamento Contínuo de Segurança**:
  - **Snyk** para detectar vulnerabilidades nas dependências em produção.
  - **Docker Bench Security** para avaliações de segurança dos contêineres em tempo de execução.
- **Plataforma de Deploy**:
  - Hospedado no **Render (PaaS)** com deploy baseado em Docker para confiabilidade.

---

## Design e Arquitetura

- **Arquitetura do Fluxo de Dados**:
  - SecureMail segue um **pipeline estruturado de processamento de dados** para analisar e-mails.
  - Abaixo está uma visão geral do fluxo de dados:
  
    ![dataflow](https://github.com/user-attachments/assets/031fe97e-8b09-4a9d-b254-2b63db6487cb)

---

## Melhorias Futuras

- **Gestão da Postura de Segurança da Aplicação (ASPM)**:
  - Integração de **Orquestração e Correlação de Segurança de Aplicações (ASOC)**.
- **Segurança da Cadeia de Suprimentos de Software**:
  - Implementação de **SLSA (Níveis da Cadeia de Suprimentos para Artefatos de Software)**.
- **Modelagem Avançada de Ameaças**:
  - Uso de **OWASP Threat Dragon** para análise estruturada de ameaças.

---

## Licença
Distribuído sob a licença **GPL-3.0**. Consulte o arquivo [LICENSE](./LICENSE) para mais detalhes.
