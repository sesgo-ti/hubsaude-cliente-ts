/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

export { SmartTokenError } from "./errors/SmartTokenError.js";
export { SigningError } from "./errors/SigningError.js";
export type { SigningStrategy } from "./signing/SigningStrategy.js";
export {
  MIN_RSA_KEY_BITS,
  MIN_EC_FIELD_BITS,
  validateMinimumKeySize,
  loadPrivateKey,
  loadPrivateKeyFromString,
  loadCertificate,
  loadCertificateFromString,
} from "./signing/PemLoader.js";
export { createPrivateKeySigningStrategy, DEFAULT_DIGEST } from "./signing/PrivateKeySigningStrategy.js";
export type { PrivateKeySigningOptions } from "./signing/PrivateKeySigningStrategy.js";
export {
  fromPrivateKey,
  fromPemFile,
  fromPemString,
  loadPkcs12,
  fromPkcs12,
  jwtAlgorithmToNode,
  fromPrivateKeyForJwt,
} from "./signing/SigningStrategyFactory.js";
export type { Pkcs12Material } from "./signing/SigningStrategyFactory.js";
export { fromPkcs11 } from "./signing/Pkcs11SigningStrategy.js";
export type { Pkcs11Options } from "./signing/Pkcs11SigningStrategy.js";
export { buildAgent, checkCertificateValidity, DEFAULT_TLS_PROTOCOL } from "./tls/SslContextFactory.js";
export type { TlsMaterial } from "./tls/SslContextFactory.js";
export {
  DEFAULT_CONNECT_TIMEOUT_MS,
  DEFAULT_REQUEST_TIMEOUT_MS,
  DEFAULT_ASSERTION_TTL_SECONDS,
  DEFAULT_MAX_RETRIES,
  resolveFaultToleranceConfig,
} from "./resilience/FaultToleranceConfig.js";
export type { FaultToleranceOptions, FaultToleranceConfig } from "./resilience/FaultToleranceConfig.js";
export type { Logger } from "./logging/Logger.js";
export { SmartTokenClient, createSmartTokenClient, DEFAULT_JWT_ALGORITHM } from "./client/SmartTokenClient.js";
export type { SmartTokenClientOptions, HubContext, TokenResponse } from "./client/SmartTokenClient.js";
