# Integração enterprise

Este guia complementa o contrato da API do `hubsaude-cliente-js` com
decisões de integração que pertencem à aplicação consumidora. O SDK não
depende de nenhum framework de aplicação, biblioteca de resiliência,
sistema de métricas ou SDK de tracing — as seções abaixo mostram como
compor essas camadas por fora, sem acoplar o SDK a uma escolha
específica.

## Ownership e ciclo de vida

`SmartTokenClient` é seguro para chamadas concorrentes (Node roda em um
único _event loop_: não há condição de corrida entre threads do sistema
operacional a evitar aqui, só a ordenação correta de promessas
concorrentes, já coberta pelo _single-flight_ interno) e deve ser uma
instância única por configuração de credencial. A aplicação é
proprietária da instância e deve fechá-la durante o encerramento:

- **aplicações long-lived** (servidores HTTP, workers): registre o
  fechamento no desligamento do processo;
- **CLIs, jobs curtos e testes**: prefira
  `await using client = await createSmartTokenClient(...)` — fecha
  automaticamente ao sair do escopo;
- não feche a instância após cada token: isso descarta a conexão HTTP
  interna e o cache compartilhado, anulando o benefício de reutilizar o
  cliente.

Em uma aplicação Node "pura", associe o fechamento a um handler de sinal:

```ts
import { createSmartTokenClient } from "hubsaude-cliente-js";

const client = await createSmartTokenClient({
  tokenEndpoint,
  clientId,
  privateKeyPem,
  certificatePem,
});

async function shutdown(): Promise<void> {
  await client.close();
  process.exit(0);
}

process.on("SIGTERM", shutdown);
process.on("SIGINT", shutdown);
```

Em frameworks com um hook de ciclo de vida explícito (ex.: um `onClose`
de plugin/servidor HTTP, ou um método de destruição de um contêiner de
injeção de dependência), registre `client.close` nesse hook em vez de um
listener de sinal manual — o efeito é o mesmo: `close()` roda uma única
vez, no encerramento da aplicação, nunca por requisição.

`close()` é idempotente, aguarda operações em voo, encerra a conexão
HTTP interna (`https.Agent`) e invalida todo o cache. Chamadas de token
posteriores ao fechamento falham explicitamente (`Error`).

## Composição de resiliência

O SDK repete automaticamente apenas **falhas transitórias de rede**
(timeout de conexão, timeout de requisição, recusa/queda de conexão TCP),
com backoff exponencial (1 s, 2 s, 4 s, ...) limitado por `maxRetries`.
Respostas HTTP recebidas do servidor de autorização — inclusive `429` e
`5xx` — **não** sofrem retry automático: a decisão de aguardar e reenviar
é do chamador. Um circuit breaker externo (ex.: `opossum`, `cockatiel`,
ou o do seu API gateway/service mesh) deve envolver a chamada ao SDK na
camada de orquestração, sem criar outro retry automático por cima do que
o SDK já faz internamente.

Ao configurar a política de resiliência externa:

1. conte como falha tanto os erros nativos de `node:http`/`node:https`
   propagados pelo SDK (ex.: `ECONNREFUSED`, `ECONNRESET`, `ETIMEDOUT`)
   quanto `SmartTokenError`;
2. não trate `SmartTokenError` de rejeição confirmada de certificado de
   cliente (mTLS) como transitório — o SDK já interrompe o retry
   internamente para esse caso porque a causa é uma configuração de
   certificado inválida, não uma instabilidade de rede; repetir não
   ajuda, corrija o certificado;
3. trate `429` conforme o header `Retry-After` (quando presente na
   mensagem de erro) e sua própria política operacional, fora do retry
   interno do SDK;
4. limite qualquer nova tentativa após um `401` recebido de um endpoint
   FHIR a uma única renovação de token: invalide o scope
   (`client.invalidateCache(scope)`), obtenha um token novo e, se o erro
   persistir, interrompa o fluxo para diagnóstico de credencial ou
   autorização — não entre em um laço de retry indefinido.

## Métricas

Instrumente a fachada da aplicação, não o SDK. Para Prometheus, siga a
convenção de nomes:

| Finalidade            | Nome recomendado                                    |
| --------------------- | --------------------------------------------------- |
| Total de solicitações | `hubsaude_<servico>_token_request_total`            |
| Duração               | `hubsaude_<servico>_token_request_duration_seconds` |
| Falhas                | `hubsaude_<servico>_token_error_total`              |

Use labels de baixa cardinalidade, como `outcome` e uma categoria fechada
de erro (ex.: `network`, `mtls_rejected`, `http_error`, `signing`). Não
use `scope`, `clientId`, token, trace-id, CPF, CNS ou outro identificador
pessoal como label: scopes livres e identificadores criam cardinalidade
não limitada; tokens e dados pessoais também violam o contrato de
segredo e a LGPD.

Os labels de identidade de serviço e ambiente devem ser `service` e
`env`.

## Trace e diagnóstico

Cada requisição HTTP do SDK (token endpoint e descoberta via
`.well-known/smart-configuration`) envia o header `traceparent` W3C. O
trace-id efetivo aparece nas mensagens de erro/retry da biblioteca
(`traceId=...`) e nos logs, quando um `logger` é configurado; informe
esse valor ao suporte do HubSaúde para correlacionar o integrador com o
`correlation-id` da plataforma.

Aplicações já instrumentadas com auto-instrumentação OpenTelemetry para
Node.js (ex.: `@opentelemetry/instrumentation-http`, que cobre
`node:http`/`node:https`) devem continuar funcionando: a instrumentação
tipicamente sobrepõe o header com o contexto do span ativo. **Esta
afirmação não foi verificada empiricamente neste projeto** — valide na
sua stack antes de depender disso.

Nunca registre `access_token`, `client_assertion`, chave privada, senha,
PIN ou o corpo bruto não sanitizado de uma resposta. O SDK já sanitiza o
que ele mesmo inclui em mensagens de erro (ver
[`docs/troubleshooting.md`](troubleshooting.md)); essa disciplina se
aplica igualmente a qualquer log adicional que a aplicação integradora
decida emitir por conta própria.

## Referências

- [README do SDK](../README.md)
- [Contrato comportamental](../ESPECIFICACAO.md)
- [Guia de troubleshooting](troubleshooting.md)
- [W3C Trace Context](https://www.w3.org/TR/trace-context/)
