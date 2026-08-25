/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

/**
 * Erro de domínio para operações utilitárias do cliente HubSaúde.
 *
 * Sinaliza falhas de parsing de PEM/JSON ou respostas inesperadas do
 * servidor de autorização, preservando a causa original (via
 * {@link Error.cause}) para facilitar o diagnóstico.
 */
export class SmartTokenError extends Error {
  /**
   * Cria o erro, opcionalmente preservando a causa original.
   *
   * @param message - descrição da falha
   * @param cause - erro original que motivou este; `undefined` quando
   *   não há causa a preservar
   */
  constructor(message: string, cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = "SmartTokenError";
  }
}
