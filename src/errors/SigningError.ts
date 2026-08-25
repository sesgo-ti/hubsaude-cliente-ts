/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

/**
 * Erro lançado quando ocorre falha durante operação de assinatura digital.
 *
 * Usado pela estratégia de assinatura ({@link SigningStrategy}) para
 * encapsular erros criptográficos de forma consistente, independente da
 * fonte da chave (memória, HSM, cofre etc.).
 */
export class SigningError extends Error {
  /**
   * Cria o erro, opcionalmente preservando a causa original.
   *
   * @param message - descrição do erro
   * @param cause - erro original que causou a falha; `undefined` quando
   *   não há causa a preservar
   */
  constructor(message: string, cause?: unknown) {
    super(message, cause !== undefined ? { cause } : undefined);
    this.name = "SigningError";
  }
}
