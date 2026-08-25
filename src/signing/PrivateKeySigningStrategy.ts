/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import { sign as cryptoSign, type KeyObject } from "node:crypto";
import { SigningError } from "../errors/SigningError.js";
import { validateMinimumKeySize } from "./PemLoader.js";
import type { SigningStrategy } from "./SigningStrategy.js";

/**
 * Algoritmo de resumo (digest) padrão — corresponde a RS384 (RSA PKCS#1
 * v1.5 + SHA-384).
 */
export const DEFAULT_DIGEST = "sha384";

/**
 * Opções de assinatura, repassadas ao `crypto.sign` nativo do Node.
 *
 * @property digest - algoritmo de resumo (ex.: `"sha256"`, `"sha384"`);
 *   padrão {@link DEFAULT_DIGEST}
 * @property dsaEncoding - formato de saída para chaves EC; use
 *   `"ieee-p1363"` para produzir a concatenação bruta `R || S` exigida
 *   pelo JWS (RFC 7518 §3.4) em vez do DER (padrão do Node)
 * @property padding - constante de padding RSA (ex.:
 *   `crypto.constants.RSA_PKCS1_PSS_PADDING`, para os algoritmos PS*)
 * @property saltLength - comprimento do salt PSS, quando `padding` acima
 *   for PSS
 */
export interface PrivateKeySigningOptions {
  digest?: string;
  dsaEncoding?: "der" | "ieee-p1363";
  padding?: number;
  saltLength?: number;
}

/**
 * Cria uma {@link SigningStrategy} que assina com uma chave privada em
 * memória, usando o `crypto` nativo do Node.
 *
 * A chave privada pode ter sido carregada de um arquivo PEM ou provir de
 * qualquer outra fonte que produza um `KeyObject` (ex.: um cofre de
 * segredos). O tamanho mínimo da chave é validado na criação
 * (fail-fast) — RSA exige ao menos 2048 bits e EC ao menos um campo de
 * 256 bits (P-256), conforme NIST SP 800-57.
 *
 * @param privateKey - chave privada a usar na assinatura
 * @param options - opções de algoritmo/formato de saída
 * @returns uma {@link SigningStrategy} síncrona pronta para uso
 * @throws {RangeError} se a chave estiver abaixo do tamanho mínimo aceito
 */
export function createPrivateKeySigningStrategy(
  privateKey: KeyObject,
  options: PrivateKeySigningOptions = {},
): SigningStrategy {
  validateMinimumKeySize(privateKey, "privateKey");
  const digest = options.digest ?? DEFAULT_DIGEST;

  return (data: Uint8Array): Uint8Array => {
    try {
      return cryptoSign(digest, data, {
        key: privateKey,
        ...(options.dsaEncoding !== undefined ? { dsaEncoding: options.dsaEncoding } : {}),
        ...(options.padding !== undefined ? { padding: options.padding } : {}),
        ...(options.saltLength !== undefined ? { saltLength: options.saltLength } : {}),
      });
    } catch (err) {
      throw new SigningError(`Falha ao assinar dados com o digest ${digest}`, err);
    }
  };
}
