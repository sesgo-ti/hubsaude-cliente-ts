/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

/**
 * Logger opcional, injetável pelo integrador (RNF-02).
 *
 * O Node não tem uma infraestrutura de log única e universal — por isso
 * a lib não escolhe uma dependência de log por conta própria (`pino`,
 * `winston`, etc.): aceita um objeto no mesmo formato do `console`
 * (todos os métodos opcionais). Quando omitido, nada é logado. Cada
 * método corresponde a um nível: `debug` (cache, construção), `info`
 * (token obtido, cache invalidado), `warn` (retries, 429), `error`
 * (falhas definitivas).
 */
export interface Logger {
  debug?(message: string, meta?: Record<string, unknown>): void;
  info?(message: string, meta?: Record<string, unknown>): void;
  warn?(message: string, meta?: Record<string, unknown>): void;
  error?(message: string, meta?: Record<string, unknown>): void;
}

/** Logger que não faz nada — usado quando o integrador não fornece um. */
export const NOOP_LOGGER: Readonly<Required<Logger>> = Object.freeze({
  debug: () => undefined,
  info: () => undefined,
  warn: () => undefined,
  error: () => undefined,
});
