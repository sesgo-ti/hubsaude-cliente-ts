/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

/**
 * Smoke test manual contra o ambiente real de homologação do HubSaúde.
 *
 * Diferente de `SmartTokenClientSimulador.test.ts` (hermético, roda
 * contra um simulador local), este bate de verdade num servidor
 * externo, fora do nosso controle — por isso nunca roda em CI, e é
 * opt-in mesmo localmente: só executa se as variáveis de ambiente
 * abaixo estiverem definidas, e pula (sem falhar) caso contrário.
 *
 * Motivo de existir: o simulador local é, por definição, uma
 * simulação — este é o único teste capaz de detectar uma divergência
 * sutil entre o comportamento simulado e o servidor de autorização
 * real.
 *
 * Nenhuma credencial fica neste repositório: certificado, chave
 * privada e client_id são sempre fornecidos por quem roda o teste,
 * nunca hardcoded.
 *
 * Variáveis de ambiente:
 * - `HOMOLOG_CLIENT_ID` (obrigatória) — client_id já registrado no
 *   homolog.
 * - `HOMOLOG_CERT_PATH` (obrigatória) — certificado de cliente (PEM)
 *   associado a esse client_id.
 * - `HOMOLOG_KEY_PATH` (obrigatória) — chave privada (PEM)
 *   correspondente.
 * - `HOMOLOG_FHIR_BASE` (opcional) — base FHIR do ambiente de
 *   homologação; padrão: `https://hub-homolog.saude.go.gov.br/`.
 * - `HOMOLOG_SCOPE` (opcional) — scope a solicitar; padrão:
 *   `system/Patient.rs`.
 *
 * Execução: `npm run test:integration:homolog`
 */
import { existsSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { createSmartTokenClient } from "../src/index.js";

const CLIENT_ID = process.env.HOMOLOG_CLIENT_ID;
const CERT_PATH = process.env.HOMOLOG_CERT_PATH;
const KEY_PATH = process.env.HOMOLOG_KEY_PATH;
const FHIR_BASE = process.env.HOMOLOG_FHIR_BASE ?? "https://hub-homolog.saude.go.gov.br/";
const SCOPE = process.env.HOMOLOG_SCOPE ?? "system/Patient.rs";

function resolveSkipReason(): string | undefined {
  if (!CLIENT_ID) return "HOMOLOG_CLIENT_ID não definida";
  if (!CERT_PATH) return "HOMOLOG_CERT_PATH não definida";
  if (!KEY_PATH) return "HOMOLOG_KEY_PATH não definida";
  if (!existsSync(CERT_PATH)) return `HOMOLOG_CERT_PATH não aponta pra um arquivo existente: ${CERT_PATH}`;
  if (!existsSync(KEY_PATH)) return `HOMOLOG_KEY_PATH não aponta pra um arquivo existente: ${KEY_PATH}`;
  return undefined;
}

const skipReason = resolveSkipReason();
if (skipReason) {
  console.warn(
    `Pulando smoke test de homologação (it/SmartTokenClientHomolog.test.ts): ${skipReason}. ` +
      "Veja o README.md, seção de testes de integração, para as variáveis de ambiente esperadas.",
  );
}

describe.skipIf(Boolean(skipReason))("SmartTokenClient contra o ambiente real de homologação", () => {
  it("obtém um access token real via mTLS", async () => {
    const client = await createSmartTokenClient({
      fhirBase: FHIR_BASE,
      clientId: CLIENT_ID as string,
      privateKeyPem: KEY_PATH as string,
      certificatePem: CERT_PATH as string,
      // O homolog real exige TLS 1.2 — TLS 1.3 é rejeitado no
      // handshake (confirmado contra o servidor real).
      tlsProtocol: "TLSv1.2",
    });

    try {
      const token = await client.obtainToken(SCOPE);
      expect(typeof token).toBe("string");
      expect(token.length).toBeGreaterThan(0);
    } finally {
      await client.close();
    }
  }, 30_000);
});
