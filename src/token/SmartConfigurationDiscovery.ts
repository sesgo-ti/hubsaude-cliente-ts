/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import * as http from "node:http";
import type { IncomingMessage } from "node:http";
import * as https from "node:https";
import { SmartTokenError } from "../errors/SmartTokenError.js";
import { sanitizeErrorResponse } from "../resilience/ErrorClassifier.js";
import { generateTraceContext, traceparent, TRACEPARENT_HEADER } from "../trace/TraceContext.js";

const HTTP_OK = 200;

/**
 * Exige que a URL use o esquema `https`, com exceção explícita para
 * `localhost`/`127.0.0.1`/`::1` (útil em desenvolvimento e testes com
 * servidor local).
 *
 * @param url - URL a validar
 * @param fieldName - nome do campo, usado na mensagem de erro
 * @throws {RangeError} se o esquema não for `https` e o host não for local
 */
export function requireHttps(url: string, fieldName: string): void {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (err) {
    throw new RangeError(`${fieldName} inválido: '${url}' não é uma URL válida`, { cause: err });
  }
  if (parsed.protocol === "https:") {
    return;
  }
  const hostLocal =
    parsed.hostname === "localhost" || parsed.hostname === "127.0.0.1" || parsed.hostname === "::1";
  if (parsed.protocol === "http:" && hostLocal) {
    return;
  }
  throw new RangeError(
    `${fieldName} deve usar o esquema https (recebido: '${url}'). O esquema http é permitido ` +
      "apenas para localhost/127.0.0.1, em desenvolvimento e testes locais.",
  );
}

/** Lê o corpo inteiro de uma resposta como texto UTF-8, sem teto de tamanho. */
async function readAllText(res: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of res as AsyncIterable<Buffer>) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * Descobre o `token_endpoint` consultando o
 * `/.well-known/smart-configuration` a partir de uma URL base FHIR.
 *
 * O valor retornado pelo servidor é validado: deve usar o esquema
 * `https` (exceção para `localhost`/`127.0.0.1`), evitando que um
 * endpoint inseguro seja adotado silenciosamente.
 *
 * @param fhirBaseUrl - URL base do servidor FHIR
 * @param agent - `https.Agent` com a configuração TLS/mTLS a usar
 * @param requestTimeoutMs - timeout da requisição, em milissegundos
 * @returns a URL do `token_endpoint` resolvida dinamicamente
 * @throws {SmartTokenError} em caso de erro de rede, resposta ≠ 200, ou
 *   ausência do campo `token_endpoint`
 * @throws {RangeError} se o `token_endpoint` descoberto não usar https
 */
export async function discoverTokenEndpoint(
  fhirBaseUrl: string,
  agent: https.Agent,
  requestTimeoutMs: number,
): Promise<string> {
  const wellKnownUrl = fhirBaseUrl.endsWith("/")
    ? `${fhirBaseUrl}.well-known/smart-configuration`
    : `${fhirBaseUrl}/.well-known/smart-configuration`;

  const trace = generateTraceContext();
  const requestOptions = {
    headers: { [TRACEPARENT_HEADER]: traceparent(trace) },
    signal: AbortSignal.timeout(requestTimeoutMs),
  };
  // Sensível ao esquema: `https:` usa o `https.Agent` com a configuração
  // TLS/mTLS; `http:` (só possível para localhost, por força de
  // `requireHttps`) usa `node:http` puro — `http.request` não aceita
  // (nem faria sentido receber) um `https.Agent`.
  const res = await new Promise<IncomingMessage>((resolve, reject) => {
    const req =
      new URL(wellKnownUrl).protocol === "https:"
        ? https.request(wellKnownUrl, { ...requestOptions, agent }, resolve)
        : http.request(wellKnownUrl, requestOptions, resolve);
    req.on("error", reject);
    req.end();
  });

  if (res.statusCode !== HTTP_OK) {
    const body = await readAllText(res).catch(() => "");
    throw new SmartTokenError(
      `Falha ao obter smart-configuration (${res.statusCode}, traceId=${trace.traceId}): ` +
        sanitizeErrorResponse(body),
    );
  }

  const bodyText = await readAllText(res).catch(() => "");
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  } catch {
    parsed = undefined;
  }
  const discovered =
    typeof parsed === "object" && parsed !== null && "token_endpoint" in parsed
      ? (parsed as Record<string, unknown>).token_endpoint
      : undefined;
  if (typeof discovered !== "string") {
    throw new SmartTokenError("A resposta de smart-configuration não contém 'token_endpoint'");
  }

  requireHttps(discovered, "token_endpoint descoberto");
  return discovered;
}
