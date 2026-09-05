/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import { constants, createPrivateKey, X509Certificate, type KeyObject } from "node:crypto";
import forge from "node-forge";
import { SmartTokenError } from "../errors/SmartTokenError.js";
import { loadPrivateKey, loadPrivateKeyFromString } from "./PemLoader.js";
import { createPrivateKeySigningStrategy, type PrivateKeySigningOptions } from "./PrivateKeySigningStrategy.js";
import type { SigningStrategy } from "./SigningStrategy.js";

/**
 * Centraliza a criação de {@link SigningStrategy} para diferentes fontes de
 * material criptográfico: chave em memória, PEM (arquivo ou string) e
 * PKCS#12.
 *
 * **HSM/PKCS#11**: coberto por `fromPkcs11`, num módulo separado
 * (`signing/Pkcs11SigningStrategy.ts`), já que depende de `pkcs11js` —
 * um pacote com binário nativo, declarado como `peerDependency`
 * opcional para não impor sua instalação a quem nunca usa HSM.
 */

/**
 * Cria uma estratégia a partir de chave privada já carregada em memória.
 *
 * Útil quando a chave foi obtida de outra fonte (ex.: cofre de segredos).
 *
 * @param privateKey - chave privada
 * @param options - opções de algoritmo (ver {@link PrivateKeySigningOptions})
 * @returns estratégia de assinatura configurada
 */
export function fromPrivateKey(privateKey: KeyObject, options?: PrivateKeySigningOptions): SigningStrategy {
  return createPrivateKeySigningStrategy(privateKey, options);
}

/**
 * Cria uma estratégia a partir de arquivo PEM.
 *
 * @param path - caminho do arquivo PEM da chave privada
 * @param password - senha para decriptar a chave (omitido se não criptografada)
 * @param options - opções de algoritmo
 * @returns estratégia de assinatura configurada
 * @throws {SmartTokenError} se o arquivo não puder ser lido/decodificado
 * @throws {RangeError} se a chave estiver abaixo do tamanho mínimo aceito
 */
export async function fromPemFile(
  path: string,
  password?: Buffer,
  options?: PrivateKeySigningOptions,
): Promise<SigningStrategy> {
  const key = await loadPrivateKey(path, password);
  return createPrivateKeySigningStrategy(key, options);
}

/**
 * Cria uma estratégia a partir de conteúdo PEM em string.
 *
 * Útil quando o PEM é obtido de variável de ambiente ou secret manager.
 *
 * @param pem - conteúdo PEM da chave privada
 * @param password - senha para decriptar (omitido se não criptografada)
 * @param source - identificador da fonte, usado na mensagem de erro
 * @param options - opções de algoritmo
 * @returns estratégia de assinatura configurada
 */
export function fromPemString(
  pem: string,
  password: Buffer | undefined,
  source: string,
  options?: PrivateKeySigningOptions,
): SigningStrategy {
  const key = loadPrivateKeyFromString(pem, password, source);
  return createPrivateKeySigningStrategy(key, options);
}

/**
 * Material extraído de um arquivo PKCS#12/PFX: a chave privada e o
 * certificado do mesmo par.
 */
export interface Pkcs12Material {
  privateKey: KeyObject;
  certificate: X509Certificate;
}

/**
 * Lê um identificador de objeto (OID) nomeado da tabela do node-forge.
 *
 * A tabela é tipada como um dicionário genérico (`{ [key: string]: string }`),
 * então o TypeScript não pode garantir estaticamente que uma chave nomeada
 * específica existe nela — na prática, os nomes usados aqui são constantes
 * do próprio node-forge e sempre estarão presentes.
 */
function oid(name: "pkcs8ShroudedKeyBag" | "keyBag" | "certBag"): string {
  // eslint-disable-next-line security/detect-object-injection -- `name` é união de 3 literais fixos, não string arbitrária
  const value = forge.pki.oids[name];
  if (value === undefined) {
    throw new Error(`OID desconhecido no node-forge: ${name}`);
  }
  return value;
}

/**
 * Extrai a chave privada e o certificado de um arquivo PKCS#12/PFX.
 *
 * O Node não lê PKCS#12 nativamente (só via `node:tls`, para uso direto
 * numa conexão) — por isso esta função usa `node-forge` para decodificar
 * o contêiner, convertendo o resultado para os tipos nativos do Node
 * (`KeyObject`, `X509Certificate`) logo em seguida.
 *
 * @param pfx - conteúdo binário do arquivo PKCS#12/PFX
 * @param passphrase - senha do arquivo
 * @returns a chave privada e o certificado extraídos
 * @throws {SmartTokenError} se a senha estiver incorreta, o arquivo for
 *   inválido, ou não contiver chave privada e certificado
 */
export function loadPkcs12(pfx: Buffer, passphrase: string): Pkcs12Material {
  let p12: forge.pkcs12.Pkcs12Pfx;
  try {
    const asn1 = forge.asn1.fromDer(pfx.toString("binary"));
    p12 = forge.pkcs12.pkcs12FromAsn1(asn1, passphrase);
  } catch (err) {
    throw new SmartTokenError(
      `Falha ao decodificar PKCS#12 (senha incorreta ou arquivo inválido?): ${(err as Error).message}`,
      err,
    );
  }

  const keyBag =
    p12.getBags({ bagType: oid("pkcs8ShroudedKeyBag") })[oid("pkcs8ShroudedKeyBag")]?.[0] ??
    p12.getBags({ bagType: oid("keyBag") })[oid("keyBag")]?.[0];
  if (keyBag?.key === undefined) {
    throw new SmartTokenError("Arquivo PKCS#12 não contém uma chave privada");
  }

  const certBag = p12.getBags({ bagType: oid("certBag") })[oid("certBag")]?.[0];
  if (certBag?.cert === undefined) {
    throw new SmartTokenError("Arquivo PKCS#12 não contém um certificado");
  }

  return {
    privateKey: createPrivateKey(forge.pki.privateKeyToPem(keyBag.key)),
    certificate: new X509Certificate(forge.pki.certificateToPem(certBag.cert)),
  };
}

/**
 * Cria uma estratégia a partir da chave privada de um arquivo PKCS#12/PFX.
 *
 * @param pfx - conteúdo binário do arquivo PKCS#12/PFX
 * @param passphrase - senha do arquivo
 * @param options - opções de algoritmo
 * @returns estratégia de assinatura configurada
 */
export function fromPkcs12(pfx: Buffer, passphrase: string, options?: PrivateKeySigningOptions): SigningStrategy {
  const { privateKey } = loadPkcs12(pfx, passphrase);
  return createPrivateKeySigningStrategy(privateKey, options);
}

/** Comprimento do salt PSS (bytes), igual ao digest, para cada algoritmo PS*. */
const PSS_SALT_LEN_256 = 32;
const PSS_SALT_LEN_384 = 48;
const PSS_SALT_LEN_512 = 64;

/**
 * Converte um algoritmo JWT (JWA, RFC 7518) para as opções de assinatura
 * correspondentes do Node (`node:crypto`).
 *
 * @param jwtAlgorithm - algoritmo no formato JWT/JWA (ex.: `"RS256"`, `"PS256"`)
 * @returns opções prontas para {@link createPrivateKeySigningStrategy}
 * @throws {SmartTokenError} se o algoritmo não for reconhecido
 */
export function jwtAlgorithmToNode(jwtAlgorithm: string): PrivateKeySigningOptions {
  switch (jwtAlgorithm.toUpperCase()) {
    case "RS256":
      return { digest: "sha256" };
    case "RS384":
      return { digest: "sha384" };
    case "RS512":
      return { digest: "sha512" };
    case "PS256":
      return { digest: "sha256", padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: PSS_SALT_LEN_256 };
    case "PS384":
      return { digest: "sha384", padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: PSS_SALT_LEN_384 };
    case "PS512":
      return { digest: "sha512", padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: PSS_SALT_LEN_512 };
    case "ES256":
      return { digest: "sha256", dsaEncoding: "ieee-p1363" };
    case "ES384":
      return { digest: "sha384", dsaEncoding: "ieee-p1363" };
    case "ES512":
      return { digest: "sha512", dsaEncoding: "ieee-p1363" };
    default:
      throw new SmartTokenError(
        `Algoritmo JWT não suportado: ${jwtAlgorithm}. Algoritmos válidos: ` +
          "RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512",
      );
  }
}

/**
 * Cria uma estratégia de assinatura a partir de um algoritmo JWT (JWA).
 *
 * @param privateKey - chave privada compatível com o algoritmo
 * @param jwtAlgorithm - algoritmo JWT (ex.: `"RS256"`, `"PS256"`, `"ES256"`)
 * @returns estratégia de assinatura configurada
 * @throws {SmartTokenError} se o algoritmo não for reconhecido
 */
export function fromPrivateKeyForJwt(privateKey: KeyObject, jwtAlgorithm: string): SigningStrategy {
  return createPrivateKeySigningStrategy(privateKey, jwtAlgorithmToNode(jwtAlgorithm));
}
