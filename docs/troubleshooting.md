# Guia de troubleshooting — TLS/mTLS e erros comuns

Este guia é direcionado ao desenvolvedor que está integrando
`hubsaude-cliente-js` com o HubSaúde, em https://hub.saude.go.gov.br.

> **Nota:** o host `hub.saude.go.gov.br` é **ilustrativo** (o mesmo dos
> exemplos do [README](../README.md)); use o endpoint informado no seu
> credenciamento.

**Importante:** em ambientes modernos (Node.js 20+, o mínimo suportado
por este SDK — ver `engines` do `package.json`), o certificado do
servidor deve ser confiável automaticamente, sem nenhuma configuração
adicional. Teste a conexão simples antes de suspeitar de bug na
aplicação.

## Diagnóstico de confiança de certificado do servidor

O certificado do servidor pode mudar ao longo do tempo. O foco desta
seção é ajudar a detectar se há um problema de confiança na cadeia TLS
(ex.: a CA raiz não é reconhecida pelo seu ambiente) — distinto de uma
rejeição de **certificado de cliente** pelo servidor em mTLS, coberto na
tabela de sintomas mais abaixo.

### Usando OpenSSL (linha de comando, Linux/macOS / shells POSIX)

```bash
openssl s_client -connect hub.saude.go.gov.br:443 -servername hub.saude.go.gov.br < /dev/null
```

- Durante a verificação, linhas como `verify return:1` para cada
  certificado da cadeia são **normais** (1 = callback retornou OK).
- No **final da saída**, procure por `Verify return code:`:
  - `Verify return code: 0 (ok)` → cadeia válida ✓
  - `Verify return code: 20 (unable to get local issuer certificate)` →
    CA raiz não reconhecida
  - `Verify return code: 21 (unable to verify the first certificate)` →
    certificado intermediário ausente

Para um check rápido de validade:

```bash
echo | openssl s_client -connect hub.saude.go.gov.br:443 -servername hub.saude.go.gov.br 2>/dev/null | openssl x509 -noout -dates
```

### Usando Node.js diretamente

Um teste mínimo, sem passar pelo SDK, isola se o problema é de confiança
de certificado ou algo específico da configuração do cliente:

```js
const https = require("node:https");

https
  .get("https://hub.saude.go.gov.br", (res) => {
    console.log("Conexão bem-sucedida! Código:", res.statusCode);
  })
  .on("error", (e) => {
    console.error("Erro:", e.code, e.message);
  });
```

- `UNABLE_TO_VERIFY_LEAF_SIGNATURE` ou `DEPTH_ZERO_SELF_SIGNED_CERT` → CA
  não confiável no trust store do processo Node.
- `CERT_HAS_EXPIRED` → certificado do servidor expirado (não confundir
  com a validação de certificado de **cliente** feita pelo próprio SDK
  na carga, RF-14).

Para inspecionar a cadeia recebida (útil para descobrir qual CA está
faltando no trust store):

```js
const tls = require("node:tls");

const socket = tls.connect(443, "hub.saude.go.gov.br", { servername: "hub.saude.go.gov.br" }, () => {
  let cert = socket.getPeerCertificate(true);
  while (cert && Object.keys(cert).length) {
    console.log(cert.subject.CN, "emitido por", cert.issuer.CN);
    if (cert.issuerCertificate === cert) break; // chegou na raiz (autoassinado)
    cert = cert.issuerCertificate;
  }
  socket.end();
});
```

## Resolução

### Confiando numa CA customizada com `serverTrustAnchor`

Para simulador local, homologação com CA interna, ou desenvolvimento com
certificados ad hoc, use a opção pública do SDK em vez de mexer no trust
store do sistema operacional ou do processo:

```ts
const client = await createSmartTokenClient({
  tokenEndpoint: "https://simulador.local/auth/token",
  clientId: "meu-sistema",
  privateKeyPem: "chave-privada.pem",
  certificatePem: "certificado.pem",
  serverTrustAnchor: "ca-custom.pem",
});
```

`serverTrustAnchor` **substitui** o trust store padrão para essa
instância — não o combine com a expectativa de que a CA de produção
continue confiável ao mesmo tempo; para isso, use o certificado de
produção real ou não configure a opção (comportamento padrão: trust
store da plataforma).

### `NODE_EXTRA_CA_CERTS` (workaround de runtime, não específico do SDK)

Quando o problema afeta o processo Node inteiro (não só este SDK), ou
como alternativa fora do código:

```bash
export NODE_EXTRA_CA_CERTS=/caminho/para/ca-raiz.pem
node minha-app.js
```

Priorize atualizar o trust store do runtime/SO para versões modernas em
vez de depender deste workaround de forma permanente.

## Tabela de sintomas

| Sintoma                                                                                                                                                 | Causa provável                                                                                                                                                                   | Solução                                                                                                                                                                                                                 |
| ------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `SmartTokenError`: "Falha ao carregar chave privada ... (senha incorreta?)"                                                                             | Chave em formato não reconhecido pelo `node:crypto`, ou senha incorreta/ausente                                                                                                  | Confirme o formato (PKCS#8/PKCS#1); force PKCS#8 com `openssl pkcs8 -topk8 -nocrypt -in key.pem -out key-pkcs8.pem`                                                                                                     |
| `SmartTokenError`: "Certificado expirado" / "Certificado ainda não é válido"                                                                            | `certificatePem`/`serverTrustAnchor` fora do período de validade (RF-14)                                                                                                         | Gere/obtenha um certificado válido; confira `openssl x509 -noout -dates -in certificado.pem`                                                                                                                            |
| `SmartTokenError`: "Chave privada não corresponde ao certificado..."                                                                                    | `certificatePem` e `privateKeyPem` não formam um par válido (RF-15) — arquivos trocados, chave corrompida ou certificado regenerado sem atualizar a chave                        | Compare a chave pública (funciona para RSA e EC): `openssl x509 -pubkey -noout -in cert.pem \| openssl pkey -pubin -outform DER \| openssl sha256` vs `openssl pkey -pubout -in key.pem -outform DER \| openssl sha256` |
| `RangeError`: chave rejeitada por tamanho insuficiente                                                                                                  | RSA < 2048 bits ou EC < P-256 (NIST SP 800-57)                                                                                                                                   | Gere uma chave RSA de ao menos 2048 bits, ou EC em P-256/P-384/P-521                                                                                                                                                    |
| Erro de conexão com causa `UNABLE_TO_VERIFY_LEAF_SIGNATURE`/`DEPTH_ZERO_SELF_SIGNED_CERT`                                                               | CA do **servidor** não confiável para este processo Node                                                                                                                         | Use `serverTrustAnchor` (simulador/homologação) ou verifique a cadeia de confiança — ver seção de diagnóstico acima                                                                                                     |
| Erro de conexão com código `ERR_SSL_TLSV1_ALERT_UNKNOWN_CA`, `ERR_SSL_SSL/TLS_ALERT_CERTIFICATE_EXPIRED` ou `ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED` | O servidor enviou um alerta TLS fatal explícito rejeitando o certificado de **cliente** (mTLS) — CA não confiável, expirado, ou nenhum certificado enviado                       | `SmartTokenError` já falha imediatamente, sem gastar tentativas de retry (RF-08.1); verifique a validade do certificado de cliente e se foi emitido pela CA esperada pelo servidor                                      |
| `SmartTokenError`: "Servidor rejeitou o certificado de cliente (mTLS), sem novas tentativas"                                                            | Mesma causa da linha acima — mensagem final já diagnosticada pelo SDK                                                                                                            | Idem                                                                                                                                                                                                                    |
| Erro de conexão com causa `ECONNREFUSED`/`ECONNRESET`/`ETIMEDOUT`, sem alerta TLS                                                                       | Firewall, endpoint incorreto, instabilidade de rede, ou (em mTLS) rejeição **ambígua** de certificado de cliente sem alerta explícito — a lib já tenta novamente automaticamente | Verifique conectividade e URL; se persistir após todas as tentativas, veja o `traceId` na mensagem final e informe ao suporte                                                                                           |
| `SmartTokenError` com status HTTP `429`                                                                                                                 | Limite de requisições excedido no servidor de autorização — o SDK não repete automaticamente respostas HTTP (RF-07.2)                                                            | Consulte o header `Retry-After` (incluído na mensagem de erro quando presente) e aguarde antes de tentar novamente                                                                                                      |
| `401` ao chamar um endpoint FHIR com um token obtido via este SDK                                                                                       | Token expirado antes do previsto, revogado, ou escopo insuficiente                                                                                                               | `client.invalidateCache(scope)` seguido de `client.obtainToken(scope)`; se o `401` persistir, trate como falha de credencial/autorização, não repita indefinidamente                                                    |
| `Error`: opções mutuamente exclusivas informadas juntas (ex.: `tokenEndpoint` + `fhirBase`)                                                             | Violação de uma das validações de construção (RF-18)                                                                                                                             | Informe exatamente uma das duas opções conflitantes                                                                                                                                                                     |
| `Error`: operação chamada após `client.close()`                                                                                                         | Uso do cliente após o encerramento explícito                                                                                                                                     | Não reutilize a instância após `close()`; crie uma nova via `createSmartTokenClient` se necessário                                                                                                                      |

## HSM/PKCS#11 (`fromPkcs11`)

| Sintoma                                                        | Causa provável                                                               | Solução                                                                                                 |
| -------------------------------------------------------------- | ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------- |
| Erro ao importar `pkcs11js`, ou `fromPkcs11` indisponível      | `pkcs11js` não instalado — é uma _peer dependency_ opcional                  | `npm install pkcs11js` além de `hubsaude-cliente-js`                                                    |
| Falha ao abrir sessão/PIN rejeitado, na chamada a `fromPkcs11` | PIN incorreto, slot/label errado, ou módulo PKCS#11 (`library`) incompatível | Confira `tokenLabel`/`slot` com a ferramenta do fabricante (ex.: `pkcs11-tool --list-slots`)            |
| Chave não encontrada                                           | `keyLabel`/`keyId` não correspondem a nenhuma chave no token                 | Ao menos um dos dois é obrigatório; confira `CKA_LABEL`/`CKA_ID` reais com `pkcs11-tool --list-objects` |

## Referências

- [README do SDK](../README.md)
- [Contrato comportamental](../ESPECIFICACAO.md)
- [Guia de integração enterprise](integracao-enterprise.md)
- [SSL Labs — auditoria de servidor TLS](https://www.ssllabs.com/ssltest/)
