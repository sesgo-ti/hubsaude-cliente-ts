/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

/** Delay base para retry exponencial, em milissegundos. */
const RETRY_BASE_DELAY_MS = 1000;

/**
 * Calcula o delay de backoff exponencial entre tentativas:
 * `1s × 2^(attempt-1)`, sem jitter.
 *
 * Regras de retry aplicadas por quem consome esta função:
 * apenas falhas transitórias de rede são retriáveis (timeout de conexão,
 * timeout de requisição e recusa/queda de conexão TCP); respostas HTTP
 * recebidas (qualquer status, inclusive 429 e 5xx) não sofrem retry
 * automático.
 *
 * @param attempt - número da tentativa que falhou (1-based)
 * @returns delay em milissegundos antes da próxima tentativa
 */
export function computeRetryDelayMs(attempt: number): number {
  return RETRY_BASE_DELAY_MS * 2 ** (attempt - 1);
}
