# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [Unreleased]

## [0.1.0] - 2026-09-03

Primeira versão funcional do SDK. Ainda não publicada no registro npm
público (ver [README](README.md#instalação)) — a série `0.x` é
provisória enquanto a API pública é estabilizada.

### Adicionado

- `createSmartTokenClient(options)` — construção assíncrona do cliente,
  com validação completa de configuração na criação (endpoint
  explícito ou descoberta via `.well-known/smart-configuration`,
  `clientId` obrigatório, fonte de assinatura exatamente uma entre
  `privateKeyPem`/`signingStrategy`, defaults tolerantes para TTL/
  `maxRetries`/margem de cache não positivos, `tokenCacheMaxEntries`
  obrigatoriamente positivo).
- `obtainToken(scope)`/`obtainTokenResponse(scope)` — obtenção de token
  via SMART Backend Services (RFC 6749 `client_credentials` + RFC 7523
  JWT bearer assertion), com montagem e assinatura do `client_assertion`,
  claims `iss`/`sub`/`aud`/`iat`/`exp`/`jti` e `hub_ctx`/`kid` opcionais.
- Cache de token por scope normalizado, com margem de renovação
  configurável, teto configurável por LRU (`tokenCacheMaxEntries`) e
  _single-flight_ por scope (deduplicação de chamadas concorrentes via
  `Map<scope, Promise>`).
- Retry com backoff exponencial (1 s/2 s/4 s/...) para falhas
  transitórias de rede, com número de tentativas configurável
  (`maxRetries`) e preservação da causa original no erro final.
- Detecção de rejeição de certificado de cliente em mTLS em dois
  níveis: alerta TLS confirmado (`ERR_SSL_*ALERT*`, interrompe o retry
  imediatamente) e caso ambíguo (conexão cai sem alerta, apenas
  sugerido na mensagem final).
- Descoberta automática do token endpoint via
  `GET <fhirBase>/.well-known/smart-configuration`, com validação de
  esquema (`https` obrigatório, exceto para `localhost`/`127.0.0.1`).
- TLS 1.3 por padrão (protocolo configurável), trust anchor customizado
  (`serverTrustAnchor`) para simulador/homologação, e suporte a mTLS via
  chave+certificado PEM em memória ou PKCS#12 (`clientPfx`).
- Suporte a quatro formatos de chave PEM (PKCS#8, PKCS#1, PKCS#8
  criptografado, OpenSSL tradicional criptografado), via `node:crypto`
  nativo, sem dependência externa de parsing PEM.
- Estratégias de assinatura (`SigningStrategy`) para as fontes: chave já
  carregada em memória (`fromPrivateKey`/`fromPrivateKeyForJwt`),
  PKCS#12 direto (`fromPkcs12`), e HSM/token via PKCS#11
  (`fromPkcs11`, com `pkcs11js` como _peer dependency_ opcional — custo
  de instalação zero para quem não usa HSM).
- Validação de consistência entre chave privada e certificado do
  cliente na construção, quando ambos são fornecidos como objetos
  diretos (RSA e EC).
- Suporte aos 9 algoritmos de assinatura JWT exigidos pela especificação
  (`RS256`/`RS384`/`RS512`, `PS256`/`PS384`/`PS512`,
  `ES256`/`ES384`/`ES512`), com padrão `RS384` e assinaturas ECDSA no
  formato bruto `R||S` (RFC 7518 §3.4).
- Rejeição fail-fast de chaves fracas (RSA < 2048 bits, EC < P-256),
  conforme NIST SP 800-57.
- `invalidateCache()`/`invalidateCache(scope)` para invalidação total ou
  por scope.
- `close()` idempotente — aguarda operações em voo, invalida o cache e
  encerra a conexão HTTP interna — e suporte a
  `Symbol.asyncDispose` (`await using`) como alternativa ao fechamento
  explícito.
- `getTokenEndpoint()`/`getJwtAlgorithm()`/`getKeyId()` para introspecção
  da configuração efetiva.
- Modelo de erros com quatro categorias: `RangeError` (valor fora do
  intervalo aceito), `Error` (precondição de configuração/estado
  violada), `SmartTokenError` (configuração criptográfica inválida,
  resposta HTTP/JSON inválida, algoritmo não suportado, rejeição
  confirmada de certificado de cliente) e `SigningError` (falha da
  estratégia de assinatura); falhas de rede propagam como os erros
  nativos de `node:http`/`node:https`, sem reembrulhar.
- Header `traceparent` (W3C Trace Context) em toda requisição HTTP
  (token endpoint e descoberta), com trace-id/span-id novos por
  tentativa e trace-id incluído nas mensagens de erro para correlação
  com o suporte do HubSaúde.
- Logger injetável opcional (`debug`/`info`/`warn`/`error`), sem
  dependência de nenhuma biblioteca de log.
- `ESPECIFICACAO.md` (contrato normativo compartilhado pelo portfólio de
  SDKs), `docs/integracao-enterprise.md` e `docs/troubleshooting.md`.

### Segurança

- Sanitização de mensagens de erro: `access_token`/`token` redigidos em
  corpos JSON e `form-urlencoded`, corpo truncado em 500 caracteres
  (redação sempre antes do truncamento).
- Senha de chave PEM e conteúdo PEM recebidos como `Buffer` e zerados
  após o uso, inclusive em caminho de erro.
- `tokenEndpoint`/`fhirBase` (e o `token_endpoint` descoberto) exigem
  esquema `https`; `http` é aceito apenas para
  `localhost`/`127.0.0.1`.
- Sem modo "confiar em tudo" (_trust-all_) na API pública.
- Fronteira entre API pública e módulos internos imposta em runtime pelo
  campo `exports` do `package.json` — um import de caminho interno
  (ex.: `hubsaude-cliente-js/dist/token/TokenCacheStrategy.js`) é
  bloqueado pelo próprio Node, não apenas por convenção.
