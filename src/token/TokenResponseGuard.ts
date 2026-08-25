/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import type { IncomingMessage } from "node:http";
import { SmartTokenError } from "../errors/SmartTokenError.js";
import { NOOP_LOGGER, type Logger } from "../logging/Logger.js";

/**
 * Valor assumido para `expires_in` (segundos) quando ausente na resposta
 * — campo opcional na RFC 6749 §5.1; 1 hora é o valor usual em
 * servidores de autorização SMART.
 */
export const DEFAULT_EXPIRES_IN_SECONDS = 3600;

/**
 * Teto de sanidade para `expires_in` (24h). Valores acima são
 * normalizados antes de alimentar o cache de tokens.
 */
export const MAX_EXPIRES_IN_SECONDS = 86_400;

/**
 * Limite (bytes) do corpo da resposta do token endpoint: 1 MiB.
 * Respostas legítimas têm poucos KiB; acima disso a leitura é abortada
 * com erro claro.
 */
export const MAX_RESPONSE_BODY_BYTES = 1_048_576;

/**
 * Aplica a política de sanidade ao campo `expires_in` de uma resposta
 * já decodificada como JSON.
 *
 * Regras: ausente → assume {@link DEFAULT_EXPIRES_IN_SECONDS} (1 hora);
 * zero, negativo ou não numérico → rejeitado; acima de
 * {@link MAX_EXPIRES_IN_SECONDS} (24h) → normalizado para o teto, com
 * aviso no logger.
 *
 * @param body - corpo da resposta já decodificado (`JSON.parse`)
 * @param logger - logger opcional; se omitido, nada é logado
 * @returns valor saneado de `expires_in`, em segundos
 * @throws {SmartTokenError} quando o valor é zero, negativo ou não
 *   numérico
 */
export function sanitizeExpiresIn(body: unknown, logger: Logger = NOOP_LOGGER): number {
  if (typeof body !== "object" || body === null || !("expires_in" in body)) {
    logger.debug?.(`Resposta sem 'expires_in' — assumindo padrão de ${DEFAULT_EXPIRES_IN_SECONDS}s`);
    return DEFAULT_EXPIRES_IN_SECONDS;
  }

  const raw = (body as Record<string, unknown>).expires_in;
  const value = typeof raw === "number" ? raw : Number(raw);
  if (!Number.isFinite(value) || value <= 0) {
    throw new SmartTokenError(
      `'expires_in' inválido na resposta do token endpoint: ${JSON.stringify(raw)} ` +
        `(esperado inteiro em 0 < x <= ${MAX_EXPIRES_IN_SECONDS})`,
    );
  }
  if (value > MAX_EXPIRES_IN_SECONDS) {
    logger.warn?.(`'expires_in'=${value}s acima do teto de sanidade — normalizando para ${MAX_EXPIRES_IN_SECONDS}s`);
    return MAX_EXPIRES_IN_SECONDS;
  }
  return Math.trunc(value);
}

/**
 * Lê o corpo de uma resposta HTTP (`node:http`/`node:https`) como texto,
 * impondo um teto de tamanho: rejeita de imediato respostas cujo
 * `Content-Length` declarado excede o limite e, para respostas sem esse
 * cabeçalho (ex.: transferência chunked), aborta a leitura assim que os
 * bytes recebidos ultrapassam o teto — sem esperar o corpo inteiro
 * chegar.
 *
 * @param res - resposta HTTP (`IncomingMessage`) a ler
 * @param maxBytes - limite máximo do corpo, em bytes (padrão
 *   {@link MAX_RESPONSE_BODY_BYTES})
 * @returns o corpo decodificado como texto UTF-8
 * @throws {SmartTokenError} se o corpo exceder `maxBytes`
 */
export async function readBoundedText(
  res: IncomingMessage,
  maxBytes: number = MAX_RESPONSE_BODY_BYTES,
): Promise<string> {
  const declaredLength = res.headers["content-length"];
  if (declaredLength !== undefined && Number(declaredLength) > maxBytes) {
    throw bodyLimitExceeded(declaredLength, maxBytes);
  }

  const chunks: Buffer[] = [];
  let received = 0;
  for await (const chunk of res as AsyncIterable<Buffer>) {
    received += chunk.byteLength;
    if (received > maxBytes) {
      res.destroy();
      throw bodyLimitExceeded(received, maxBytes);
    }
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function bodyLimitExceeded(received: number | string, maxBytes: number): SmartTokenError {
  return new SmartTokenError(
    `Resposta do token endpoint excede o limite de ${maxBytes} bytes (recebido/declarado: ${received} bytes)`,
  );
}
