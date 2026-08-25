/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import type { KeyObject, X509Certificate } from "node:crypto";
import { SmartTokenError } from "../errors/SmartTokenError.js";

const SUPPORTED_KEY_TYPES = new Set(["rsa", "rsa-pss", "ec"]);

/**
 * Verifica que a chave privada corresponde à chave pública do certificado.
 *
 * Detecta erros de configuração (arquivos trocados, chave corrompida,
 * certificado regenerado sem atualizar a chave) na inicialização, em vez
 * de só quando o servidor de autorização rejeitar o `client_assertion`.
 *
 * @param privateKey - chave privada a validar
 * @param certificate - certificado X.509 contendo a chave pública
 *   correspondente
 * @throws {SmartTokenError} se o tipo de chave não for suportado para esta
 *   verificação, ou se a chave e o certificado não formarem um par válido
 */
export function verifyKeyPair(privateKey: KeyObject, certificate: X509Certificate): void {
  const type = privateKey.asymmetricKeyType;
  if (type === undefined || !SUPPORTED_KEY_TYPES.has(type)) {
    throw new SmartTokenError(`Tipo de chave não suportado para validação de consistência: ${type}`);
  }
  if (!certificate.checkPrivateKey(privateKey)) {
    throw new SmartTokenError(
      "Chave privada não corresponde ao certificado (arquivos trocados, chave " +
        "corrompida ou certificado regenerado sem atualizar a chave?)",
    );
  }
}
