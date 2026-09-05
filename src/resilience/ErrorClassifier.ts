/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import { SmartTokenError } from "../errors/SmartTokenError.js";
import { NOOP_LOGGER, type Logger } from "../logging/Logger.js";

/** Código HTTP: Rate Limit Exceeded. */
export const HTTP_TOO_MANY_REQUESTS = 429;

/** Limite máximo para sanitização de respostas de erro. */
const MAX_ERROR_RESPONSE_LENGTH = 500;

/**
 * Códigos de erro (`err.code`) do Node tratados como falha transitória
 * de rede — os produzidos por `node:https`:
 * `ECONNREFUSED` (conexão recusada), `ECONNRESET`/`EPIPE` (conexão
 * derrubada abruptamente) e `ETIMEDOUT` (timeout de baixo nível, tanto
 * do próprio SO quanto do temporizador manual de `connectTimeoutMs` em
 * `SmartTokenClient`, que reusa esse mesmo código de propósito).
 */
const TRANSIENT_ERROR_CODES = new Set(["ECONNREFUSED", "ECONNRESET", "ETIMEDOUT", "EPIPE"]);

/**
 * Códigos de erro de verificação de certificado X.509 do OpenSSL/Node —
 * indicam que foi **o cliente** que rejeitou o certificado do
 * **servidor** (trust anchor ausente/incorreto, certificado expirado
 * etc.), nunca o contrário. Lista não exaustiva dos códigos mais comuns.
 */
const TLS_CERT_VERIFICATION_ERROR_CODES = new Set([
  "UNABLE_TO_VERIFY_LEAF_SIGNATURE",
  "UNABLE_TO_GET_ISSUER_CERT_LOCALLY",
  "CERT_HAS_EXPIRED",
  "CERT_NOT_YET_VALID",
  "DEPTH_ZERO_SELF_SIGNED_CERT",
  "SELF_SIGNED_CERT_IN_CHAIN",
  "CERT_UNTRUSTED",
  "CERT_CHAIN_TOO_LONG",
  "ERR_TLS_CERT_ALTNAME_INVALID",
]);

/**
 * Identifica um `err.code` de alerta TLS fatal **recebido do peer**
 * (RFC 8446 §6.2) relacionado a rejeição de certificado — usado para
 * detectar com confiança que o **servidor** rejeitou o certificado de
 * **cliente** apresentado no mTLS (RF-08.1).
 *
 * Usa um padrão, não uma lista fixa de códigos exatos, porque o formato
 * varia por versão do OpenSSL/protocolo negociado —
 * `ERR_SSL_TLSV1_ALERT_UNKNOWN_CA` (CA não
 * confiável), `ERR_SSL_SSL/TLS_ALERT_CERTIFICATE_EXPIRED` (certificado
 * expirado — note a barra "/" literal no código) e
 * `ERR_SSL_TLSV13_ALERT_CERTIFICATE_REQUIRED` (nenhum certificado
 * enviado) foram os três observados diretamente. Uma lista fixa desses
 * literais ficaria refém da formatação exata de uma versão específica
 * do OpenSSL — o mesmo tipo de fragilidade entre versões que já nos
 * custou um bug real com o `undici` (ver nota em RASTREABILIDADE.md).
 * Em vez disso, casamos pela substância do nome do alerta (RFC 8446
 * §6.2 nomeia oito alertas fatais relacionados a certificado:
 * `bad_certificate`, `unsupported_certificate`, `certificate_revoked`,
 * `certificate_expired`, `certificate_unknown`, `unknown_ca`,
 * `access_denied`, `certificate_required` — todos contêm "CERTIFICATE",
 * exceto `unknown_ca` e `access_denied`, tratados à parte), excluindo
 * deliberadamente alertas genéricos de handshake sem relação com
 * certificado (`handshake_failure`, `protocol_version`,
 * `insufficient_security` etc.), que não contêm nenhuma dessas
 * substrings.
 *
 * @param code - `err.code` a inspecionar
 * @returns `true` se o código corresponde a um alerta TLS de rejeição
 *   de certificado recebido do peer
 */
function isPeerCertificateAlertCode(code: string): boolean {
  return (
    code.startsWith("ERR_SSL_") &&
    code.includes("ALERT") &&
    (code.includes("CERTIFICATE") || code.includes("UNKNOWN_CA") || code.includes("ACCESS_DENIED"))
  );
}

function errorCode(err: Error): string | undefined {
  const code = (err as NodeJS.ErrnoException).code;
  return typeof code === "string" ? code : undefined;
}

/** Percorre `err` e sua cadeia de `cause`, um `Error` por vez. */
function* causeChain(err: unknown): Generator<Error> {
  let current: unknown = err;
  while (current instanceof Error) {
    yield current;
    current = current.cause;
  }
}

/**
 * Identifica se a cadeia de causas indica que **o cliente** rejeitou o
 * certificado do **servidor** (validação local do trust anchor) — nunca
 * o contrário.
 *
 * @param err - erro capturado na tentativa
 * @returns `true` quando o padrão indica rejeição do certificado do
 *   servidor pelo cliente
 */
export function isClientSideCertificateValidationFailure(err: unknown): boolean {
  for (const e of causeChain(err)) {
    const code = errorCode(e);
    if (code !== undefined && TLS_CERT_VERIFICATION_ERROR_CODES.has(code)) {
      return true;
    }
  }
  return false;
}

/**
 * Identifica falhas transitórias de rede elegíveis a retry: timeout
 * (`AbortSignal.timeout` usado com `https.request`, reportado como
 * `AbortError`) e recusa/queda de conexão TCP (`ECONNREFUSED`,
 * `ECONNRESET`, `ETIMEDOUT`, `EPIPE`). Falhas de verificação de
 * certificado do servidor pelo cliente nunca são consideradas
 * transitórias — um problema de confiança na cadeia TLS não se resolve
 * tentando de novo.
 *
 * @param err - erro capturado na tentativa
 * @returns `true` quando a falha é transitória de rede
 */
export function isTransientNetworkFailure(err: unknown): boolean {
  if (isClientSideCertificateValidationFailure(err)) {
    return false;
  }
  for (const e of causeChain(err)) {
    if (e.name === "AbortError") {
      return true;
    }
    const code = errorCode(e);
    if (code !== undefined && TRANSIENT_ERROR_CODES.has(code)) {
      return true;
    }
  }
  return false;
}

/**
 * Detecta com **confiança** (não heurística) que o servidor rejeitou o
 * certificado de cliente apresentado no mTLS — RF-08.1: o servidor
 * enviou um alerta TLS fatal específico sobre certificado, capturado via
 * `node:https`/`node:tls` (ver {@link isPeerCertificateAlertCode}).
 *
 * Diferente de {@link isLikelyClientCertificateRejection} (que só
 * sugere, para o caso ambíguo em que a conexão simplesmente cai sem
 * alerta nenhum), esta função só retorna `true` quando o sinal é
 * inequívoco — seguro para interromper o retry imediatamente.
 *
 * @param err - erro capturado na tentativa
 * @param mtlsConfigured - se a conexão tinha certificado de cliente
 *   configurado
 * @returns `true` quando um alerta TLS de certificado foi recebido do
 *   servidor com mTLS configurado
 */
export function isConfirmedClientCertificateRejection(err: unknown, mtlsConfigured: boolean): boolean {
  if (!mtlsConfigured) {
    return false;
  }
  for (const e of causeChain(err)) {
    const code = errorCode(e);
    if (code !== undefined && isPeerCertificateAlertCode(code)) {
      return true;
    }
  }
  return false;
}

/**
 * Heurística — para o caso **ambíguo** em que a conexão cai sem nenhum
 * alerta TLS específico — para sinalizar que uma falha de conexão
 * *pode* ter sido causada pelo servidor rejeitando o certificado de
 * cliente no mTLS.
 *
 * **Limitação real**: nem todo servidor que
 * rejeita um certificado de cliente envia um alerta TLS formal antes de
 * fechar a conexão — alguns (inclusive o próprio `https.Server` do Node,
 * quando a verificação do certificado do peer falha após o handshake
 * criptográfico já ter avançado) simplesmente derrubam a conexão
 * abruptamente. Nesse caso o sinal do lado do cliente é **idêntico** ao
 * de qualquer outra queda de conexão comum (`ECONNRESET`/`EPIPE`) — sem
 * a granularidade que
 * {@link isConfirmedClientCertificateRejection} tem para o caso de um
 * alerta real. Por isso esta função só pode **sugerir a possibilidade**,
 * nunca confirmá-la, e só quando mTLS estava de fato configurado na
 * conexão.
 *
 * Ao contrário de {@link isConfirmedClientCertificateRejection}, esta
 * implementação **não interrompe o retry** com base nela — o sinal é
 * ambíguo demais para justificar desistir cedo de algo que pode ser só
 * uma instabilidade de rede comum. Em vez disso, o chamador deve usar
 * esta função só para enriquecer a mensagem de erro final, após todas
 * as tentativas se esgotarem.
 *
 * @param err - erro capturado na tentativa
 * @param mtlsConfigured - se a conexão tinha certificado de cliente
 *   configurado
 * @returns `true` quando o padrão sugere a possibilidade (não a
 *   certeza) de rejeição do certificado de cliente pelo servidor
 */
export function isLikelyClientCertificateRejection(err: unknown, mtlsConfigured: boolean): boolean {
  if (!mtlsConfigured || isClientSideCertificateValidationFailure(err)) {
    return false;
  }
  for (const e of causeChain(err)) {
    const code = errorCode(e);
    if (code === "ECONNRESET" || code === "EPIPE") {
      return true;
    }
  }
  return false;
}

/**
 * Sanitiza a resposta de erro para evitar vazamento de tokens em logs e
 * mensagens de erro (RNF-02).
 *
 * A redação de tokens é aplicada **antes** do truncamento, garantindo
 * que nenhum token apareça mesmo em respostas longas.
 *
 * @param responseBody - corpo da resposta HTTP (aceita ausente/vazio)
 * @returns resposta sanitizada
 */
export function sanitizeErrorResponse(responseBody: string | null | undefined): string {
  if (responseBody === null || responseBody === undefined || responseBody === "") {
    return "<empty>";
  }
  const redacted = responseBody
    .replace(/("(?:access_token|token)")\s*:\s*"[^"]*"/g, '$1:"[REDACTED]"')
    .replace(/(access_token|token)=[^&\s]*/g, "$1=[REDACTED]");
  return redacted.length > MAX_ERROR_RESPONSE_LENGTH ? `${redacted.slice(0, MAX_ERROR_RESPONSE_LENGTH)}...` : redacted;
}

/**
 * Materializa uma resposta HTTP de erro (status ≠ 200) em
 * {@link SmartTokenError}, registrando o log adequado no logger
 * informado: `warn` para rate limit (HTTP 429, sem retry automático) e
 * `error` para os demais.
 *
 * @param statusCode - status HTTP da resposta
 * @param body - corpo da resposta (já lido como string)
 * @param retryAfter - valor do header `Retry-After`, se presente
 * @param traceId - trace-id W3C enviado na requisição
 * @param logger - logger opcional; se omitido, nada é logado
 * @returns erro pronto para ser lançado pelo chamador
 */
export function httpFailure(
  statusCode: number,
  body: string | null | undefined,
  retryAfter: string | null,
  traceId: string,
  logger: Logger = NOOP_LOGGER,
): SmartTokenError {
  if (statusCode === HTTP_TOO_MANY_REQUESTS) {
    logger.warn?.("Rate limit (HTTP 429) — sem retry automático", { traceId });
  } else {
    logger.error?.(`Falha ao obter token: HTTP ${statusCode}`, { statusCode, traceId });
  }

  const retryAfterPart = retryAfter !== null ? ` (Retry-After: ${retryAfter.trim()})` : "";
  const hint =
    statusCode === HTTP_TOO_MANY_REQUESTS
      ? " Rate limit atingido; a decisão de aguardar e reenviar é do chamador."
      : "";
  return new SmartTokenError(
    `Falha ao obter token: HTTP ${statusCode}${retryAfterPart} (traceId=${traceId}) — ` +
      `${sanitizeErrorResponse(body)}${hint}`,
  );
}
