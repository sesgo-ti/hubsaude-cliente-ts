/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import type { KeyObject, X509Certificate } from "node:crypto";
import { Agent as HttpsAgent, type AgentOptions } from "node:https";
import type { SecureVersion } from "node:tls";
import { SmartTokenError } from "../errors/SmartTokenError.js";

/** Protocolo TLS padrão utilizado quando nenhum é especificado. */
export const DEFAULT_TLS_PROTOCOL: SecureVersion = "TLSv1.3";

/**
 * Material de configuração TLS/mTLS para a conexão com o servidor de
 * autorização.
 *
 * O `https.Agent` nativo do Node aceita todo esse material diretamente
 * nas opções de conexão — por isso um único conjunto de campos, todos
 * opcionais, cobre as combinações de RF-10/RF-11.
 *
 * @property serverTrustAnchor - certificado(s) de CA customizados para
 *   validar o servidor; omitido usa o trust store padrão do Node
 * @property clientKey - chave privada do cliente para mTLS (par com
 *   `clientCertificate`); alternativa a `clientPfx`
 * @property clientCertificate - certificado do cliente para mTLS (par com
 *   `clientKey`)
 * @property clientPfx - alternativa a `clientKey`/`clientCertificate`:
 *   contêiner PKCS#12/PFX completo, repassado diretamente ao Node (não
 *   precisa de extração — só a assinatura do JWT precisa disso)
 * @property clientPfxPassphrase - senha do `clientPfx`
 * @property tlsProtocol - versão mínima do TLS (padrão
 *   {@link DEFAULT_TLS_PROTOCOL})
 */
export interface TlsMaterial {
  serverTrustAnchor?: string | Buffer | X509Certificate | readonly (string | Buffer | X509Certificate)[];
  clientKey?: KeyObject | string | Buffer;
  clientCertificate?: X509Certificate | string | Buffer;
  clientPfx?: Buffer;
  clientPfxPassphrase?: string;
  tlsProtocol?: SecureVersion;
}

function toPemCert(value: string | Buffer | X509Certificate): string | Buffer {
  return typeof value === "object" && "toString" in value && "subject" in value
    ? (value as X509Certificate).toString()
    : (value as string | Buffer);
}

function toPemKey(value: KeyObject | string | Buffer): string | Buffer {
  if (typeof value === "string" || Buffer.isBuffer(value)) {
    return value;
  }
  return value.export({ type: "pkcs8", format: "pem" });
}

/**
 * Constrói um `https.Agent` (nativo do Node) configurado com o material
 * TLS/mTLS fornecido, pronto para ser passado como `agent` em
 * `https.request`.
 *
 * A precedência é: `clientPfx` (se presente) tem prioridade sobre
 * `clientKey`/`clientCertificate` — fornecer os dois é um erro de
 * configuração do chamador. Sem nenhum material de cliente, a conexão é
 * TLS unidirecional (comportamento retrocompatível, RF-11.4).
 *
 * O timeout de conexão (`connectTimeoutMs`) **não** é configurado aqui —
 * o `https.Agent` não tem uma opção de "connect timeout" própria (seu
 * `timeout` é um timeout de inatividade do socket, não uma janela de
 * conexão). É aplicado por requisição em `SmartTokenClient` (`doObtainToken`),
 * via um temporizador manual amarrado ao evento `socket`/`secureConnect`.
 *
 * @param material - configuração de TLS/mTLS
 * @returns um `https.Agent` pronto para uso com `https.request`
 * @throws {Error} se `clientPfx` e `clientKey`/`clientCertificate` forem
 *   fornecidos simultaneamente (precondição de configuração violada,
 *   não falha de parsing/protocolo — mesma categoria das checagens de
 *   exclusividade mútua em `SmartTokenClient.create`)
 */
export function buildAgent(material: TlsMaterial): HttpsAgent {
  const hasPfx = material.clientPfx !== undefined;
  const hasKeyPair = material.clientKey !== undefined || material.clientCertificate !== undefined;
  if (hasPfx && hasKeyPair) {
    throw new Error("Defina clientPfx OU clientKey/clientCertificate para mTLS, não ambos");
  }

  const options: AgentOptions = {
    minVersion: material.tlsProtocol ?? DEFAULT_TLS_PROTOCOL,
  };

  if (material.serverTrustAnchor !== undefined) {
    options.ca = Array.isArray(material.serverTrustAnchor)
      ? material.serverTrustAnchor.map(toPemCert)
      : toPemCert(material.serverTrustAnchor as string | Buffer | X509Certificate);
  }

  if (hasPfx) {
    options.pfx = material.clientPfx;
    options.passphrase = material.clientPfxPassphrase;
  } else if (material.clientKey !== undefined && material.clientCertificate !== undefined) {
    options.key = toPemKey(material.clientKey);
    options.cert = toPemCert(material.clientCertificate);
  }

  return new HttpsAgent(options);
}

/**
 * Verifica o período de validade do certificado (fail-fast, RF-14).
 *
 * Aplicado em todos os pontos de entrada de certificados — tanto os
 * carregados de arquivo PEM ({@link PemLoader.loadCertificate}) quanto
 * os usados diretamente para mTLS.
 *
 * @param cert - certificado a verificar
 * @param source - identificador da fonte, usado na mensagem de erro
 * @throws {SmartTokenError} se o certificado estiver expirado ou ainda
 *   não for válido
 */
export function checkCertificateValidity(cert: X509Certificate, source: string): void {
  const now = Date.now();
  if (now < Date.parse(cert.validFrom)) {
    throw new SmartTokenError(`Certificado ainda não é válido: ${source}`);
  }
  if (now > Date.parse(cert.validTo)) {
    throw new SmartTokenError(`Certificado expirado: ${source}`);
  }
}
