/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import { randomBytes } from "node:crypto";

/** Nome do header HTTP de contexto de trace (W3C Trace Context). */
export const TRACEPARENT_HEADER = "traceparent";

const VERSION = "00";
const FLAGS_NOT_SAMPLED = "00";
const TRACE_ID_BYTES = 16;
const SPAN_ID_BYTES = 8;

/**
 * Contexto de trace [W3C Trace Context](https://www.w3.org/TR/trace-context/)
 * gerado localmente para uma requisição HTTP do cliente.
 *
 * Gerado uma vez por requisição (inclusive cada retry gera o seu). O
 * HubSaúde deriva o identificador de correlação de cada requisição
 * exclusivamente do header `traceparent`.
 *
 * @property traceId - identificador do trace: 32 caracteres hexadecimais
 *   minúsculos, nunca todo-zeros
 * @property spanId - identificador do span (parent-id no header): 16
 *   caracteres hexadecimais minúsculos, nunca todo-zeros
 */
export interface TraceContext {
  readonly traceId: string;
  readonly spanId: string;
}

function randomLowerHex(numBytes: number): string {
  let hex: string;
  do {
    hex = randomBytes(numBytes).toString("hex");
  } while (/^0+$/.test(hex));
  return hex;
}

/**
 * Gera um novo contexto de trace com trace-id e span-id aleatórios
 * criptograficamente (`node:crypto.randomBytes`).
 *
 * @returns novo contexto de trace, nunca todo-zeros
 */
export function generateTraceContext(): TraceContext {
  return Object.freeze({
    traceId: randomLowerHex(TRACE_ID_BYTES),
    spanId: randomLowerHex(SPAN_ID_BYTES),
  });
}

/**
 * Monta o valor do header `traceparent` no formato
 * `00-<trace-id>-<parent-id>-00`, onde parent-id é o `spanId` do
 * contexto.
 *
 * @param context - contexto de trace (normalmente vindo de
 *   {@link generateTraceContext})
 * @returns valor pronto para envio no header `traceparent`
 */
export function traceparent(context: TraceContext): string {
  return `${VERSION}-${context.traceId}-${context.spanId}-${FLAGS_NOT_SAMPLED}`;
}
