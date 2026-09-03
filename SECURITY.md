# Política de Segurança — hubsaude-cliente-js

## Versões suportadas

Apenas a versão **MAJOR mais recente** publicada recebe
correções de segurança. Versões anteriores são consideradas fim-de-vida
(EOL) a partir do lançamento de uma nova MAJOR.

Enquanto o projeto estiver na série `0.x` (pré-`1.0.0`), esta política se
aplica à MINOR mais recente publicada, já que MINORs podem incluir
mudanças incompatíveis nessa fase (ver [CONTRIBUTING.md](CONTRIBUTING.md)).

| Versão / série                   | Suportada |
| -------------------------------- | --------- |
| Série `0.x` (MINOR mais recente) | ✅        |
| Série `0.x` (MINORs anteriores)  | ❌        |
| `1.x+` (MAJOR mais recente)      | ✅        |
| `1.x+` (MAJORs anteriores)       | ❌        |

## Como reportar uma vulnerabilidade

Pedimos **divulgação responsável**. Não abra issues públicas para
vulnerabilidades de segurança. Use um dos canais abaixo.

### Canal preferencial — GitHub Security Advisories

Abra um _private security advisory_ no repositório deste projeto (aba
"Security" → "Report a vulnerability").

Vantagens:

- Histórico privado, com auditoria
- Permite atribuição de CVE pelo GitHub
- Integra com o fluxo de patch

### Canal alternativo — e-mail

Caso não use o GitHub, envie para:

**`<e-mail de contato de segurança a definir>`**

> Este canal ainda não foi confirmado para `hubsaude-cliente-js`. Não
> copie o contato usado por outro projeto do mesmo portfólio sem validar
> antes que é o mesmo canal monitorado para esta lib — atualize esta
> seção assim que o contato correto for definido.

Inclua, sempre que possível:

- Descrição do problema e impacto estimado
- Passos para reproduzir (PoC mínimo)
- Versões afetadas
- Sugestão de mitigação, se houver

## Processo de resposta

| Etapa                             | Prazo-alvo           |
| --------------------------------- | -------------------- |
| Acuso de recebimento              | 3 dias úteis         |
| Avaliação inicial e classificação | 10 dias úteis        |
| Correção em ramo privado          | conforme severidade  |
| Coordenação de divulgação         | acordada com o autor |
| Release com correção + advisory   | conforme severidade  |

Severidade segue [CVSS v3.1](https://www.first.org/cvss/v3-1/specification-document).

## Reconhecimento

Pesquisadores que reportarem vulnerabilidades de boa-fé serão
reconhecidos publicamente no advisory, salvo solicitação explícita de
anonimato.

## Escopo

Este documento cobre o pacote publicado no registro npm como
`hubsaude-cliente-js`, incluindo todo o código distribuído em `dist/`
(ver o campo `files` do `package.json`).

Dependências de terceiros usadas apenas em desenvolvimento (lint, testes,
mutation testing, geração de SBOM) estão fora do escopo direto desta
política — vulnerabilidades nelas devem ser reportadas ao projeto de
origem, embora sejam monitoradas via `npm audit` como parte da
manutenção do repositório.
