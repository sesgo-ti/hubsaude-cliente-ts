/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import { createPrivateKey, X509Certificate, type KeyObject } from "node:crypto";
import { readFile } from "node:fs/promises";
import { SmartTokenError } from "../errors/SmartTokenError.js";
import { checkCertificateValidity } from "../tls/SslContextFactory.js";

/**
 * Tamanho mínimo aceito, em bits, para o módulo de chaves RSA
 * (NIST SP 800-57).
 */
export const MIN_RSA_KEY_BITS = 2048;

/**
 * Tamanho mínimo aceito, em bits, para o campo da curva de chaves EC
 * (equivalente a P-256, NIST SP 800-57).
 */
export const MIN_EC_FIELD_BITS = 256;

/**
 * Tamanho do campo, em bits, das curvas nomeadas reconhecidas (nomes no
 * estilo OpenSSL, que é como o Node expõe `asymmetricKeyDetails.namedCurve`).
 *
 * Curvas fora desta tabela não são validadas quanto ao tamanho — mesma
 * postura do Node/OpenSSL para tipos de chave não reconhecidos.
 */
const EC_CURVE_FIELD_BITS: Readonly<Record<string, number>> = {
  secp192r1: 192,
  secp224r1: 224,
  prime256v1: 256, // P-256
  secp384r1: 384, // P-384
  secp521r1: 521, // P-521
};

/**
 * Valida o tamanho mínimo de uma chave privada (fail-fast).
 *
 * Chaves RSA com módulo menor que {@link MIN_RSA_KEY_BITS} bits e chaves EC
 * com campo menor que {@link MIN_EC_FIELD_BITS} bits (P-256) são
 * consideradas criptograficamente fracas (NIST SP 800-57) e rejeitadas.
 * Chaves de outros algoritmos, ou curvas EC não reconhecidas, não são
 * validadas.
 *
 * @param key - chave privada a validar
 * @param source - identificador da fonte, usado na mensagem de erro
 * @throws {RangeError} se a chave estiver abaixo do tamanho mínimo aceito
 */
export function validateMinimumKeySize(key: KeyObject, source: string): void {
  const details = key.asymmetricKeyDetails;
  if (key.asymmetricKeyType === "rsa" && details?.modulusLength !== undefined) {
    const bits = details.modulusLength;
    if (bits < MIN_RSA_KEY_BITS) {
      throw new RangeError(
        `Chave RSA de ${bits} bits rejeitada: o tamanho mínimo aceito é ` +
          `${MIN_RSA_KEY_BITS} bits (NIST SP 800-57). Fonte: ${source}`,
      );
    }
    return;
  }
  if (key.asymmetricKeyType === "ec" && details?.namedCurve !== undefined) {
    const bits = EC_CURVE_FIELD_BITS[details.namedCurve];
    if (bits !== undefined && bits < MIN_EC_FIELD_BITS) {
      throw new RangeError(
        `Chave EC com campo de ${bits} bits rejeitada: a curva mínima aceita é ` +
          `P-256 (${MIN_EC_FIELD_BITS} bits, NIST SP 800-57). Fonte: ${source}`,
      );
    }
  }
}

/**
 * Zera um buffer de senha/PIN para minimizar exposição em memória.
 *
 * @param password - buffer a zerar; aceita `undefined`
 */
export function clearPassword(password: Buffer | undefined): void {
  password?.fill(0);
}

/**
 * Carrega chave privada de arquivo PEM.
 *
 * Detecta automaticamente o formato — PKCS#8 (com ou sem senha), PKCS#1 e
 * o formato tradicional OpenSSL criptografado — delegando ao parser PEM
 * nativo do Node (`node:crypto`, baseado em OpenSSL).
 *
 * O arquivo é lido como bytes brutos (nunca como `string`) e o buffer é
 * zerado ao final, em sucesso ou erro; o `password`, se fornecido, também é
 * zerado ao final desta chamada — não o reutilize.
 *
 * @param path - caminho do arquivo PEM
 * @param password - senha para chaves criptografadas; zerada após o uso
 * @returns a chave privada carregada
 * @throws {SmartTokenError} se o arquivo não puder ser lido/decodificado,
 *   a chave exigir senha não fornecida, a senha estiver incorreta, ou o
 *   formato não for suportado
 * @throws {RangeError} se a chave estiver abaixo do tamanho mínimo aceito
 */
export async function loadPrivateKey(path: string, password?: Buffer): Promise<KeyObject> {
  const raw = await readFile(path);
  try {
    return loadPrivateKeyFromBuffer(raw, password, path);
  } finally {
    raw.fill(0);
    clearPassword(password);
  }
}

/**
 * Carrega chave privada a partir de conteúdo PEM já em memória (string).
 *
 * Preferir {@link loadPrivateKey} ou passar o conteúdo como `Buffer`
 * sempre que possível: por ser `string` (imutável), o conteúdo aqui não
 * pode ser zerado e permanece no heap até a coleta de lixo.
 *
 * @param pem - conteúdo PEM
 * @param password - senha para chaves criptografadas; zerada após o uso
 * @param source - identificador da fonte, usado na mensagem de erro
 * @returns a chave privada carregada
 * @throws {SmartTokenError} nas mesmas condições de {@link loadPrivateKey}
 * @throws {RangeError} se a chave estiver abaixo do tamanho mínimo aceito
 */
export function loadPrivateKeyFromString(
  pem: string,
  password: Buffer | undefined,
  source: string,
): KeyObject {
  const buffer = Buffer.from(pem, "utf8");
  try {
    return loadPrivateKeyFromBuffer(buffer, password, source);
  } finally {
    buffer.fill(0);
    clearPassword(password);
  }
}

function loadPrivateKeyFromBuffer(
  pemBuffer: Buffer,
  password: Buffer | undefined,
  source: string,
): KeyObject {
  if (pemBuffer.length === 0) {
    throw new SmartTokenError(`Arquivo PEM vazio ou inválido: ${source}`);
  }
  if (password === undefined && pemBuffer.includes("ENCRYPTED")) {
    throw new SmartTokenError(`Chave criptografada requer senha: ${source}`);
  }

  let key: KeyObject;
  try {
    key =
      password !== undefined
        ? createPrivateKey({ key: pemBuffer, format: "pem", passphrase: password })
        : createPrivateKey({ key: pemBuffer, format: "pem" });
  } catch (err) {
    const hint = password !== undefined ? " (senha incorreta?)" : "";
    throw new SmartTokenError(
      `Falha ao carregar chave privada de ${source}${hint}: ${(err as Error).message}`,
      err,
    );
  }

  validateMinimumKeySize(key, source);
  return key;
}

/**
 * Carrega certificado X.509 de arquivo PEM, validando o período de
 * validade (fail-fast).
 *
 * @param path - caminho do arquivo PEM do certificado
 * @returns o certificado X.509 carregado
 * @throws {SmartTokenError} se o arquivo não contiver um certificado X.509
 *   válido, ou se estiver fora do período de validade
 */
export async function loadCertificate(path: string): Promise<X509Certificate> {
  const pem = await readFile(path, "utf8");
  return loadCertificateFromString(pem, path);
}

/**
 * Carrega certificado X.509 de conteúdo PEM em string, validando o
 * período de validade (fail-fast).
 *
 * @param pem - conteúdo PEM
 * @param source - identificador da fonte, usado na mensagem de erro
 * @returns o certificado X.509 carregado
 * @throws {SmartTokenError} nas mesmas condições de {@link loadCertificate}
 */
export function loadCertificateFromString(pem: string, source: string): X509Certificate {
  let cert: X509Certificate;
  try {
    cert = new X509Certificate(pem);
  } catch (err) {
    throw new SmartTokenError(`Arquivo PEM não contém certificado X.509 válido: ${source}`, err);
  }
  checkCertificateValidity(cert, source);
  return cert;
}
