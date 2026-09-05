# hubsaude-cliente-js

[![Version](https://img.shields.io/badge/Version-0.1.0-yellow)](CHANGELOG.md)
[![Node.js 22+](https://img.shields.io/badge/Node.js-22%2B-339933)](https://nodejs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-7.x-3178C6)](https://www.typescriptlang.org/)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://www.apache.org/licenses/LICENSE-2.0)

Cliente TypeScript/Node.js (consumível também por JavaScript puro) para
obtenção de tokens de acesso ao HubSaúde via
[SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)
(SMART-on-FHIR). Encapsula a montagem do JWT _client assertion_, sua
assinatura e a troca pelo _access token_ no endpoint OAuth 2.0.

O contrato comportamental está em [`ESPECIFICACAO.md`](ESPECIFICACAO.md)
— requisitos normativos compartilhados pelo portfólio oficial de SDKs
do HubSaúde.

## Instalação

```bash
npm install hubsaude-cliente-js
```

`0.1.0` é uma versão de desenvolvimento — a série `0.x` é provisória (ver
seção abaixo) e o pacote ainda não foi publicado no registro npm público.
Até a primeira publicação, instale a partir de um tarball gerado por
`npm pack` neste repositório, ou aponte para o Git diretamente.

## Política da API pública

Enquanto a biblioteca estiver na série `0.x`, sua API é provisória:
versões `MINOR` podem introduzir mudanças incompatíveis e versões `PATCH`
preservam compatibilidade. A partir de `1.0.0`, a evolução seguirá
estritamente o
[Versionamento Semântico 2.0.0](https://semver.org/lang/pt-BR/).

Todos os tipos e funções reexportados pelo ponto de entrada do pacote
(`import ... from "hubsaude-cliente-js"`, ver o campo `exports` do
`package.json`) integram a API pública. Qualquer caminho de import mais
profundo (ex.: `hubsaude-cliente-js/dist/token/TokenCacheStrategy.js`) é
bloqueado pelo próprio Node em runtime — não é só uma convenção de
organização de pastas. A criação de `SmartTokenClient` é feita
**exclusivamente** por `createSmartTokenClient(options)`; a classe não
tem construtor público, reforçado tanto em tempo de compilação quanto em
runtime.

## Uso básico

```ts
import { createSmartTokenClient } from "hubsaude-cliente-js";

const client = await createSmartTokenClient({
  tokenEndpoint: "https://hub.saude.go.gov.br/auth/token",
  clientId: "meu-sistema",
  privateKeyPem: "chave-privada.pem",
  certificatePem: "certificado.pem",
});

const token = await client.obtainToken("system/Patient.rs");
```

A instância é reutilizável e segura para chamadas concorrentes (Node
roda em um único _event loop_, então não há condição de corrida entre
threads do sistema operacional a evitar aqui). Mantém cache do token por
scope, renovado conforme margem de expiração configurável, e executa
_retries_ com _backoff_ exponencial em falha transitória de rede.
Reutilize a mesma instância pelo ciclo de vida da aplicação e chame
`close()` uma única vez no encerramento.

## Ciclo de vida, cache e erros

`close()` é idempotente, aguarda operações em voo, encerra a conexão
HTTP interna e invalida todo o cache. Após o fechamento, novas
obtenções de token falham explicitamente. Em aplicações _long-lived_,
feche a instância no desligamento do processo (ex.: handler de
`SIGTERM`); em CLIs, jobs curtos e testes, prefira
`await using client = await createSmartTokenClient(...)` — o
gerenciamento de recursos nativo do JS/TS moderno, que fecha
automaticamente ao sair do escopo.

As operações de token podem propagar:

| Tipo                                                                            | Situação                                                                                                                                                                                |
| ------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Erro nativo do `node:http`/`node:https` (ex.: `Error` com `code: "ECONNRESET"`) | Falha de rede não recuperada pelos _retries_ internos — propagado sem reembrulhar                                                                                                       |
| `SmartTokenError`                                                               | Configuração criptográfica inválida, resposta HTTP/JSON inválida, algoritmo não suportado, ou rejeição confirmada do certificado de cliente pelo servidor (RF-08.1 — ver seção de mTLS) |
| `SigningError`                                                                  | Falha da estratégia criptográfica ao assinar o `client_assertion`                                                                                                                       |
| `RangeError`                                                                    | Valor fora do intervalo aceito (chave fraca, `hub_ctx` malformado, `tokenCacheMaxEntries` não positivo)                                                                                 |
| `Error`                                                                         | Precondição de configuração/estado violada (ex.: opções mutuamente exclusivas informadas juntas, cliente já fechado)                                                                    |

Node não tem um equivalente a interromper uma thread em espera; se você
cancelar a operação externamente (ex.: envolvendo a chamada com seu
próprio timeout), a rejeição se propaga normalmente pelo `await`.

Após receber `401` ao usar um token em um endpoint FHIR, invalide a
entrada antes de obter um novo token:

```ts
client.invalidateCache("system/Patient.rs");
const renewedToken = await client.obtainToken("system/Patient.rs");
```

Não repita indefinidamente após um novo `401`: trate a recorrência como
falha de credencial, consentimento ou autorização. Consulte o
[guia de integração enterprise](docs/integracao-enterprise.md) para
lifecycle, circuit breaker, métricas e observabilidade.

## Fontes de chave (`SigningStrategy`)

A escolha de _onde_ a chave privada reside é a decisão arquitetural
mais relevante para uma integração de produção:

| Fonte                | Quando usar                                          | Exposição da chave                                                         |
| -------------------- | ---------------------------------------------------- | -------------------------------------------------------------------------- |
| PEM (PKCS#8)         | Prototipação e testes                                | Arquivo em claro no disco                                                  |
| PEM com senha        | Mitigação adicional quando PEM é inevitável          | Cifrada em disco; senha em runtime                                         |
| PKCS#12 direto       | **Recomendado para produção** com chaves em software | Decodificada em memória do processo a cada uso; não persiste em disco      |
| HSM via PKCS#11      | Produção com chave não-exportável                    | Nunca sai do hardware — via `SigningStrategy` própria, não embutida no SDK |
| Cofre (ex.: OpenBao) | Chave provisionada por cofre central                 | Buscada em runtime; nunca em disco                                         |

### Tamanho mínimo de chave

Chaves fracas são rejeitadas no carregamento e na construção da
estratégia de assinatura (fail-fast, `RangeError`), conforme NIST SP
800-57:

| Algoritmo | Mínimo aceito             |
| --------- | ------------------------- |
| RSA       | 2048 bits (módulo)        |
| EC        | P-256 (campo de 256 bits) |

Chaves fornecidas por uma `SigningStrategy` própria (HSM, cofre) não
passam por esta validação — a política de tamanho fica a cargo da fonte.

### PKCS#12 direto

```ts
import { readFile } from "node:fs/promises";
import { createSmartTokenClient, fromPkcs12 } from "hubsaude-cliente-js";

const pfx = await readFile("certificado.pfx");

const client = await createSmartTokenClient({
  tokenEndpoint: "https://hub.saude.go.gov.br/auth/token",
  clientId: "meu-sistema",
  signingStrategy: fromPkcs12(pfx, "senha-pfx"),
  // mTLS com o mesmo contêiner PKCS#12 (opcional)
  clientPfx: pfx,
  clientPfxPassphrase: "senha-pfx",
});
```

### HSM via PKCS#11

O Node não tem suporte nativo a PKCS#11. Por isso `pkcs11js` — a lib de referência para
Node.js citada na especificação compartilhada pelos SDKs (§9.2) — é uma
**peer dependency opcional**: instale-a separadamente apenas se for usar
HSM/token; quem não usa não paga nenhum custo de instalação (confirmado
empiricamente — sem ela, o `npm install` não baixa nem tenta compilar
nada):

```bash
npm install hubsaude-cliente-js pkcs11js
```

```ts
import { createSmartTokenClient, fromPkcs11 } from "hubsaude-cliente-js";

const signingStrategy = await fromPkcs11({
  library: "/usr/lib/softhsm/libsofthsm2.so", // módulo PKCS#11 do fabricante
  tokenLabel: "meu-token", // ou slot: 0
  keyLabel: "minha-chave-hsm", // e/ou keyId: Buffer.from(...)
  pin: "123456",
  jwtAlgorithm: "ES384", // padrão: RS384
});

const client = await createSmartTokenClient({
  tokenEndpoint: "https://hub.saude.go.gov.br/auth/token",
  clientId: "meu-sistema",
  signingStrategy,
});
```

A chave é localizada por `keyLabel` (`CKA_LABEL`), `keyId` (`CKA_ID`),
ou os dois juntos — útil porque muitos HSMs/smart cards pareiam chave
privada e certificado pelo `CKA_ID` em vez de (ou além do label), e
alguns fabricantes não preenchem o label de forma consistente. Ao menos
um dos dois é obrigatório.

A sessão com o token é aberta e autenticada uma única vez, nesta
chamada (fail-fast: PIN incorreto ou chave inexistente falham aqui, não
na primeira assinatura), e reaproveitada para todas as assinaturas
subsequentes. `client.close()` libera essa sessão automaticamente — a
`SigningStrategy` devolvida por `fromPkcs11` tem um método `close`
opcional que `SmartTokenClient.close()` invoca ao encerrar (não é parte
do tipo `SigningStrategy` em si; é uma convenção que qualquer estratégia
customizada pode adotar do mesmo jeito, anexando `close` à função que
devolve). Se preferir orquestrar o acesso ao HSM você mesmo (sidecar
dedicado, API de KMS em nuvem), continua podendo fornecer sua própria
`SigningStrategy` assíncrona em vez de `fromPkcs11`.

### Cofre / chave já carregada

```ts
import { createPrivateKey } from "node:crypto";
import { createSmartTokenClient, fromPrivateKey } from "hubsaude-cliente-js";

const pem = await baoClient.getPrivateKey("secret/data/hubsaude/key");
const signingStrategy = fromPrivateKey(createPrivateKey(pem));

const client = await createSmartTokenClient({
  tokenEndpoint: "https://hub.saude.go.gov.br/auth/token",
  clientId: "meu-sistema",
  signingStrategy,
});
```

`fromPrivateKey` sem opções assina com RSA PKCS#1 v1.5 + SHA-384
(compatível com o algoritmo padrão do cliente, RS384). Se o servidor
exigir outro algoritmo, use `fromPrivateKeyForJwt(key, jwtAlgorithm)` e
informe o mesmo valor em `jwtAlgorithm` nas opções do cliente.

### PEM com senha

```ts
const client = await createSmartTokenClient({
  tokenEndpoint: "https://hub.saude.go.gov.br/auth/token",
  clientId: "meu-sistema",
  privateKeyPem: "chave-encrypted.pem",
  privateKeyPassword: Buffer.from("minha-senha"),
});
```

## Configuração avançada

```ts
const client = await createSmartTokenClient({
  tokenEndpoint: "https://hub.saude.go.gov.br/auth/token",
  clientId: "meu-sistema",
  privateKeyPem: "chave-privada.pem",
  certificatePem: "certificado.pem",
  serverTrustAnchor: "ca-custom.pem", // simulador/homologação
  tlsProtocol: "TLSv1.2", // padrão: "TLSv1.3"
  connectTimeoutMs: 10_000,
  requestTimeoutMs: 30_000,
  assertionTtlSeconds: 120, // TTL do JWT
  enableTokenCache: true,
  tokenCacheMarginSeconds: 30, // margem de renovação
  tokenCacheMaxEntries: 1_000, // teto LRU por scope
  maxRetries: 3,
  jwtAlgorithm: "RS384", // padrão: RS384 (HubSaúde aceita RS384/ES384)
  keyId: "minha-chave-2026", // kid no header do JWT (opcional)
  hubContext: { ig: "hemograma", versao: "0.0.1" }, // claim hub_ctx
});
```

O endpoint deve usar `https`; o esquema `http` é aceito apenas para
`localhost`/`127.0.0.1` (desenvolvimento e testes locais).

Valores não positivos em `assertionTtlSeconds`, `maxRetries` e
`tokenCacheMarginSeconds` são substituídos pelos padrões de 60 s, 3
tentativas totais e 30 s, respectivamente. `tokenCacheMaxEntries` deve
ser positivo; valor inválido faz `createSmartTokenClient` rejeitar a
`Promise` com `RangeError`.

### Contexto de Guia de Implementação (`hub_ctx`)

O claim proprietário `hub_ctx` declara o Guia de Implementação (IG) e a
versão pretendidos na sessão (concern `client-assertion-contexto-ig.md`
§3.4). Configure com `hubContext: { ig, versao }`: o `ig` usa
minúsculas, dígitos e hífen (ex.: `"hemograma"`) e a `versao` é SemVer
completo `MAJOR.MINOR.PATCH` (ex.: `"0.0.1"`). Quando não configurado, o
claim é omitido — servidores que o exigem rejeitarão o assertion.

### Identificador de chave (`kid`)

Quando o servidor de autorização publica múltiplas chaves (JWKS), use
`keyId: "..."` para incluir o header `kid` no _client assertion_,
permitindo que o servidor selecione a chave pública correta para
validar a assinatura. Se não configurado, o header contém apenas `alg`
e `typ`.

### Descoberta automática do endpoint

Em vez de fixar `tokenEndpoint`, informe a base FHIR — o cliente
resolve via `.well-known/smart-configuration`:

```ts
const options = { fhirBase: "https://hub.saude.go.gov.br" };
```

### `serverTrustAnchor` — quando usar

Em produção o HubSaúde usa CA já presente no trust store padrão do
Node. Use `serverTrustAnchor` apenas em testes locais com o simulador,
homologação com CA interna, ou desenvolvimento com certificados ad hoc.

## Preparação de certificados PFX/P12 → PEM

Útil quando a chave precisa ser materializada em PEM. Se você usa
PKCS#12 direto ou HSM, ignore esta seção.

```bash
# Chave privada (atenção: -nodes salva em claro)
openssl pkcs12 -in certificado.pfx -nocerts -nodes -out chave-privada.pem

# Certificado público
openssl pkcs12 -in certificado.pfx -clcerts -nokeys -out certificado.pem

# (Opcional) Forçar PKCS#8
openssl pkcs8 -topk8 -nocrypt -in chave-privada.pem -out chave-pkcs8.pem

# (Opcional) Cifrar a chave em AES-256
openssl pkcs8 -topk8 -v2 aes-256-cbc -in chave-privada.pem -out chave-encrypted.pem
```

## Resiliência em produção

A biblioteca já cobre cache de token + _retries_ com _backoff_. Para
proteção adicional contra falhas prolongadas do servidor de
autorização, combine com um _circuit breaker_ externo na camada de
orquestração (ex.: `opossum`, `cockatiel`, ou o do seu API
gateway/service mesh) — o SDK não embute nenhum. O
[guia de integração enterprise](docs/integracao-enterprise.md) descreve
ownership, composição de resiliência e métricas sem acoplar o SDK a um
framework.

## Correlação e observabilidade (`traceparent`)

O HubSaúde ignora headers como `X-Correlation-Id` enviados pelo
cliente: a correlação é derivada **exclusivamente** do contexto de
trace W3C ([W3C Trace Context](https://www.w3.org/TR/trace-context/)).
Por isso, toda requisição HTTP desta biblioteca (token endpoint e
descoberta via `.well-known/smart-configuration`) envia o header
`traceparent` no formato `00-<trace-id>-<parent-id>-00`, com trace-id
(16 bytes) e span-id (8 bytes) gerados criptograficamente
(`node:crypto.randomBytes`) **por requisição** — cada retry carrega um
par novo. Não há dependência de nenhum SDK OpenTelemetry.

A flag `sampled` é `00` (_not sampled_), coerente com a semântica do
W3C Trace Context §3.2.2.5.1: a biblioteca não grava spans.

**Como usar com o suporte**: em falhas, o trace-id enviado aparece nas
mensagens de erro/retry da biblioteca (`traceId=...`) e nos logs, se um
`logger` foi configurado. Informe esse valor ao suporte do HubSaúde —
ele permite localizar, na plataforma, o `correlation-id` e os registros
da requisição correspondente.

Aplicações já instrumentadas com auto-instrumentação OpenTelemetry para
Node.js (ex.: `@opentelemetry/instrumentation-http`, que cobre
`node:http`/`node:https`) devem continuar funcionando: a instrumentação
tipicamente sobrepõe o header com o contexto do span ativo. **Diferente
das demais afirmações deste README, esta não foi verificada
empiricamente neste projeto** — valide na sua stack antes de depender
disso.

## Troubleshooting

| Sintoma                                                                                      | Causa provável                                                                                                                                                                                                  | Solução                                                                                                                                   |
| -------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `SmartTokenError`: "Falha ao carregar chave privada ... (senha incorreta?)"                  | Chave em formato não reconhecido pelo `node:crypto`, ou senha incorreta/ausente                                                                                                                                 | Confirme o formato (PKCS#8/PKCS#1); force PKCS#8 com `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem`                       |
| Erro de conexão com causa `UNABLE_TO_VERIFY_LEAF_SIGNATURE` (ou similar)                     | CA do servidor não confiável                                                                                                                                                                                    | Use `serverTrustAnchor` (simulador/homologação) ou verifique a cadeia de confiança                                                        |
| `SigningError`: "Falha ao assinar dados..." mesmo com chave/certificado corretos             | Certificado não corresponde à chave privada                                                                                                                                                                     | Compare _modulus_: `openssl x509 -noout -modulus -in cert.pem \| openssl md5` vs `openssl rsa -noout -modulus -in key.pem \| openssl md5` |
| `SmartTokenError`: "Servidor rejeitou o certificado de cliente (mTLS), sem novas tentativas" | O servidor de autorização enviou um alerta TLS explícito rejeitando o certificado de cliente (CA não confiável, expirado, ou nenhum certificado enviado) — RF-08.1, a lib já falha rápido sem gastar tentativas | Verifique a validade do certificado de cliente e se ele foi emitido pela CA que o servidor espera                                         |
| Erro de conexão com causa `ECONNREFUSED`/`ECONNRESET`/`ETIMEDOUT`                            | Firewall, endpoint incorreto, ou instabilidade de rede — a lib já tenta novamente automaticamente                                                                                                               | Verifique conectividade e URL; se persistir após todas as tentativas, veja o `traceId` na mensagem final                                  |

Para diagnóstico aprofundado de **confiança de certificado SSL/TLS**
(com exemplos em bash, PowerShell, Node.js e OpenSSL), consulte o
[guia de troubleshooting TLS](docs/troubleshooting.md).

Para experimentar o fluxo completo localmente sem ambiente de
homologação, use a ferramenta irmã
[`hubsaude-cliente-cli`](https://github.com/sesgo-ti/hubsaude-cliente-cli).

## Build e testes

```bash
npm ci
npm run typecheck
npm test
npm run test:coverage
```

`test:coverage` aplica um gate mínimo de 85% de cobertura de linha.

### Teste de integração com o simulador local

Além da suíte unitária (mockada, sem rede), há uma suíte de integração
real em `test/integration/` — sem mocks, batendo de verdade num
simulador local do HubSaúde via mTLS, incluindo descoberta de endpoint
via `.well-known/smart-configuration`. Excluída explicitamente do
`npm test`/`npm run test:coverage` padrão.

Requer a CLI `hubsaude`, que provisiona e gerencia o simulador como
processo local:

```bash
curl -fsSL https://raw.githubusercontent.com/kyriosdata/runner/main/install.sh | bash
```

Instala o binário em `~/.local/bin` (sem `sudo`). Confirme com:

```bash
hubsaude version
```

Com a CLI instalada:

```bash
npm run test:integration
```

Sem a CLI instalada, a suíte é **pulada automaticamente** (não falha),
com um aviso explicando como instalá-la. O teste sobe e encerra o
simulador sozinho; note que ele é gerenciado como um processo único por
máquina — rodar a suíte localmente reinicia qualquer instância do
simulador já em execução para outro propósito.

### Smoke test manual contra homologação real

Além do simulador local (hermético, mas ainda uma simulação), há um
smoke test à parte que bate no ambiente real de homologação —
`test/integration/SmartTokenClientHomolog.test.ts`. Detecta divergências sutis entre o
comportamento simulado e o servidor de autorização real que o simulador
não reproduziria.

Nunca roda em CI, e é opt-in mesmo localmente: só executa se as
variáveis de ambiente abaixo estiverem definidas (nenhuma credencial
fica neste repositório):

| Variável            | Obrigatória | Descrição                                                 |
| ------------------- | ----------- | --------------------------------------------------------- |
| `HOMOLOG_CLIENT_ID` | sim         | `client_id` já registrado no homolog                      |
| `HOMOLOG_CERT_PATH` | sim         | Certificado de cliente (PEM) associado a esse `client_id` |
| `HOMOLOG_KEY_PATH`  | sim         | Chave privada (PEM) correspondente                        |
| `HOMOLOG_FHIR_BASE` | não         | Padrão: `https://hub-homolog.saude.go.gov.br/`            |
| `HOMOLOG_SCOPE`     | não         | Padrão: `system/Patient.rs`                               |

```bash
HOMOLOG_CLIENT_ID=... \
HOMOLOG_CERT_PATH=/caminho/para/certificado.pem \
HOMOLOG_KEY_PATH=/caminho/para/chave.pem \
npm run test:integration:homolog
```

Sem essas variáveis, a suíte é pulada automaticamente com um aviso.

### Qualidade de código

```bash
npm run lint          # ESLint — só verifica
npm run lint:fix       # ESLint — corrige o que der
npm run format:check   # Prettier — só verifica
npm run format         # Prettier — reformata
npm run depcruise       # regras de dependência entre módulos (sem ciclos, sem módulo de apoio importar de client/)
```

`eslint.config.js` inclui `eslint-plugin-security`, focado em padrões
arriscados (uso de `eval`, caminho de arquivo não-literal, etc.).

**Limitação atual conhecida**: este projeto usa `typescript@^7.0.2`, uma
versão muito recente do compilador — o `typescript-eslint` ainda não a
suporta (ver comentário no topo de `eslint.config.js`), então as regras
específicas de TypeScript não estão ativas por enquanto, só as regras
genéricas de JavaScript e de segurança.

### Mutation testing

```bash
npm run test:mutation
```

Não roda como parte de `npm test` nem de CI — é uma ferramenta de
diagnóstico sob demanda, não um gate obrigatório.

### SBOM

```bash
npm run sbom
```

Gera `sbom.json` (formato CycloneDX) a partir da árvore de dependências
atual — útil para auditoria, não gerado automaticamente em build/CI.

### Documentação de API (TypeDoc)

Ainda não configurado — **bloqueado por incompatibilidade de versão,
não só por falta de configuração**: `typedoc@0.28.20` (a versão estável
mais recente no momento) quebra já na inicialização contra
`typescript@^7.0.2`
(`TypeError: Cannot read properties of undefined (reading
'PropertyDeclaration')`), porque declara suporte via `peerDependencies`
só até `typescript@6.0.x`. Mesmo padrão de outras ferramentas do
ecossistema que ainda não acompanharam essa versão do TypeScript (ver
a limitação do `typescript-eslint` acima). Reavaliar quando o TypeDoc
publicar uma versão com suporte a TS 7.x.

## Publicação de nova versão (release)

Ainda não há um workflow de release automatizado neste repositório. O
processo pretendido:

```bash
npm version <major|minor|patch>
git push --follow-tags
npm publish
```

com a publicação promovida por CI a partir da tag, incluindo SBOM
CycloneDX — mesmo padrão do restante do portfólio.

## Referências

| Especificação                                                                                                         | Descrição                                            |
| --------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------- |
| [SMART Backend Services](https://hl7.org/fhir/smart-app-launch/backend-services.html)                                 | Perfil HL7 FHIR para autenticação backend-to-backend |
| [RFC 6749](https://datatracker.ietf.org/doc/html/rfc6749)                                                             | OAuth 2.0 (`client_credentials`)                     |
| [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519)                                                             | JSON Web Token (JWT)                                 |
| [RFC 7521](https://datatracker.ietf.org/doc/html/rfc7521) / [RFC 7523](https://datatracker.ietf.org/doc/html/rfc7523) | Assertion Framework e JWT Bearer Assertion           |

O [guia de integração enterprise](docs/integracao-enterprise.md)
complementa essas referências com lifecycle, resiliência, métricas e
integração com contêineres.

## Licença e contribuição

Apache License 2.0 — ver [`LICENSE`](LICENSE) e [`NOTICE`](NOTICE).
Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).

- `CONTRIBUTING.md` — fluxo e DCO
- `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1
- `SECURITY.md` — divulgação responsável de vulnerabilidades
