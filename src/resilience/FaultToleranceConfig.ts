/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

/** Timeout padrão de conexão TCP, em milissegundos. */
export const DEFAULT_CONNECT_TIMEOUT_MS = 10_000;

/** Timeout padrão de requisição HTTP completa, em milissegundos. */
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

/** TTL padrão do `client_assertion` JWT, em segundos. */
export const DEFAULT_ASSERTION_TTL_SECONDS = 60;

/** Número máximo padrão de tentativas em caso de falha transitória. */
export const DEFAULT_MAX_RETRIES = 3;

/**
 * Opções de tolerância a falhas aceitas na construção do cliente — todas
 * opcionais, com os padrões acima.
 */
export interface FaultToleranceOptions {
  connectTimeoutMs?: number;
  requestTimeoutMs?: number;
  assertionTtlSeconds?: number;
  maxRetries?: number;
}

/**
 * Configuração de tolerância a falhas resolvida: imutável, com os padrões
 * já aplicados.
 */
export interface FaultToleranceConfig {
  readonly connectTimeoutMs: number;
  readonly requestTimeoutMs: number;
  readonly assertionTtlSeconds: number;
  readonly maxRetries: number;
}

/**
 * Resolve a configuração de tolerância a falhas a partir das opções
 * informadas, substituindo pelos padrões os valores ausentes e os
 * valores não positivos de `assertionTtlSeconds`/`maxRetries`.
 *
 * @param options - opções de tolerância a falhas, parcialmente informadas
 * @returns configuração resolvida, imutável
 */
export function resolveFaultToleranceConfig(options: FaultToleranceOptions): FaultToleranceConfig {
  return Object.freeze({
    connectTimeoutMs: options.connectTimeoutMs ?? DEFAULT_CONNECT_TIMEOUT_MS,
    requestTimeoutMs: options.requestTimeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS,
    assertionTtlSeconds:
      options.assertionTtlSeconds !== undefined && options.assertionTtlSeconds > 0
        ? options.assertionTtlSeconds
        : DEFAULT_ASSERTION_TTL_SECONDS,
    maxRetries:
      options.maxRetries !== undefined && options.maxRetries > 0
        ? options.maxRetries
        : DEFAULT_MAX_RETRIES,
  });
}
