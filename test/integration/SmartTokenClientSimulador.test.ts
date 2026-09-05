/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

/**
 * Teste de integração real contra o simulador local do HubSaúde,
 * gerenciado pela CLI `hubsaude`. Não mocka nada: sobe o simulador como
 * processo local de verdade, extrai o certificado do próprio servidor
 * em runtime, registra um client descartável e obtém um access token
 * de ponta a ponta (descoberta SMART, assinatura do `client_assertion`,
 * handshake mTLS e requisição HTTP reais).
 *
 * Fica em `test/integration/`, excluído explicitamente do `include`
 * padrão em `vitest.config.ts` — roda apenas via `npm run
 * test:integration`, nunca como parte de `npm test`/`npm run
 * test:coverage`. Consulte o README.md (seção de testes de
 * integração) para instruções de instalação da CLI.
 *
 * Pula a suíte inteira, sem falhar, quando o binário `hubsaude` não
 * está disponível no PATH — mantém `npm run test:integration`
 * executável (com um aviso claro) em máquinas/CI sem a CLI instalada.
 *
 * Aviso importante sobre o simulador: é um processo único por máquina,
 * não uma instância isolada por execução — `hubsaude simulador start`
 * substitui qualquer instância anterior. Rodar esta suíte localmente
 * reinicia/encerra qualquer simulador que já estivesse em execução
 * para outro propósito (ex.: uma sessão manual de testes em outro
 * terminal). `afterAll` encerra o simulador ao final da suíte; se o
 * processo de teste for interrompido de forma abrupta (ex.: SIGKILL),
 * rode `hubsaude simulador stop` manualmente depois.
 *
 * Porta fixa (não alocada dinamicamente): a versão do simulador usada
 * aqui publica `issuer`/`token_endpoint` fixos em `https://localhost:8443`
 * em `/.well-known/smart-configuration`, **independentemente** da porta
 * efetivamente passada em `--port`; e o próprio `/auth/token` valida a
 * claim `aud` do `client_assertion` contra esse mesmo valor fixo — uma
 * tentativa de obter token com o simulador rodando em qualquer outra
 * porta é rejeitada com `401 invalid_client` ("Audience inválida"),
 * mesmo com a conexão TCP/TLS bem-sucedida. Por isso este teste sobe o
 * simulador especificamente em `8443`: é a única porta para a qual a
 * descoberta via `fhirBase` resolve um `token_endpoint` de fato
 * alcançável nesta versão.
 */
import { execFileSync } from "node:child_process";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import * as https from "node:https";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { connect as tlsConnect } from "node:tls";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createSmartTokenClient, type SmartTokenClient } from "../../src/index.js";

const SIMULATOR_PORT = 8443;
const SIMULATOR_HOST = "localhost";
const SIMULATOR_FHIR_BASE = `https://${SIMULATOR_HOST}:${SIMULATOR_PORT}`;
const CLIENT_ID = "it-suite-client";
const SCOPE = "system/Patient.rs";

let hubsaudeAvailable = true;
try {
  execFileSync("hubsaude", ["version"], { stdio: "ignore" });
} catch {
  hubsaudeAvailable = false;
  console.warn(
    "CLI `hubsaude` não encontrada no PATH: pulando a suíte de integração com o " +
      "simulador (test/integration/SmartTokenClientSimulador.test.ts). Veja o README.md, seção de " +
      "testes de integração, para instruções de instalação.",
  );
}

function runHubsaude(args: string[]): void {
  execFileSync("hubsaude", args, { stdio: "ignore" });
}

function openssl(args: string[]): void {
  execFileSync("openssl", args, { stdio: "ignore" });
}

/**
 * Requisição HTTPS simples com verificação de certificado do servidor
 * desabilitada — usada só nos dois pontos que precisam ocorrer antes de
 * o certificado do simulador ter sido extraído/estabelecido como
 * confiável: a checagem de prontidão em `/metadata` e o registro do
 * client em `/clients/register`. A obtenção do token em si passa pelo
 * cliente público desta lib, com verificação de certificado real via
 * `serverTrustAnchor`.
 */
function insecureRequest(
  path: string,
  method: "GET" | "POST",
  headers?: Record<string, string>,
  body?: string,
): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = https.request(
      { host: SIMULATOR_HOST, port: SIMULATOR_PORT, path, method, headers, rejectUnauthorized: false },
      (res) => {
        const chunks: Buffer[] = [];
        res.on("data", (chunk: Buffer) => chunks.push(chunk));
        res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
      },
    );
    req.on("error", reject);
    req.end(body);
  });
}

/**
 * Espera o simulador responder em `/metadata`. `hubsaude simulador
 * start` só retorna quando o simulador já está pronto, então isto é
 * uma rede de segurança adicional, não o mecanismo principal de
 * espera.
 */
async function waitUntilReady(maxAttempts = 20, delayMs = 500): Promise<void> {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    try {
      const { status } = await insecureRequest("/metadata", "GET");
      if (status === 200) {
        return;
      }
    } catch {
      // simulador ainda não aceita conexões; tenta de novo
    }
    await new Promise((resolve) => setTimeout(resolve, delayMs));
  }
  throw new Error(`Simulador não respondeu em /metadata após ${maxAttempts} tentativas`);
}

/**
 * Extrai o certificado do próprio servidor do simulador diretamente da
 * conexão TLS (abordagem portável entre máquinas/CI): conecta com
 * verificação de certificado desabilitada só para ler
 * `getPeerCertificate()` e reexportar o DER recebido como PEM. Evita
 * depender de qualquer caminho de instalação da CLI — detalhe interno
 * que não é uma API pública estável.
 */
function extractServerCertificatePem(): Promise<string> {
  return new Promise((resolve, reject) => {
    const socket = tlsConnect({ host: SIMULATOR_HOST, port: SIMULATOR_PORT, rejectUnauthorized: false }, () => {
      const peerCertificate = socket.getPeerCertificate();
      socket.end();
      if (peerCertificate.raw === undefined) {
        reject(new Error("Não foi possível obter o certificado do servidor do simulador"));
        return;
      }
      const base64Lines = peerCertificate.raw.toString("base64").match(/.{1,64}/g) ?? [];
      resolve(`-----BEGIN CERTIFICATE-----\n${base64Lines.join("\n")}\n-----END CERTIFICATE-----\n`);
    });
    socket.on("error", reject);
  });
}

const describeAgainstSimulador = describe.skipIf(!hubsaudeAvailable);

describeAgainstSimulador("SmartTokenClient contra o simulador HubSaúde (real, sem mocks)", () => {
  let dir: string;
  let client: SmartTokenClient | undefined;

  beforeAll(async () => {
    dir = await mkdtemp(join(tmpdir(), "hubsaude-it-"));
    const clientKeyPath = join(dir, "client-key.pem");
    const clientCertPath = join(dir, "client-cert.pem");

    // Par chave/certificado autoassinado descartável, gerado por
    // execução — nunca reaproveita certificado pessoal/real.
    openssl([
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-keyout",
      clientKeyPath,
      "-out",
      clientCertPath,
      "-days",
      "1",
      "-nodes",
      "-subj",
      `/CN=${CLIENT_ID}`,
    ]);

    try {
      runHubsaude(["simulador", "stop"]);
    } catch {
      // nenhuma instância anterior em execução — nada a fazer
    }
    runHubsaude(["simulador", "start", `--port=${SIMULATOR_PORT}`]);
    await waitUntilReady();

    const serverCertPem = await extractServerCertificatePem();
    const serverCertPath = join(dir, "simulador-server-cert.pem");
    await writeFile(serverCertPath, serverCertPem, "utf8");

    const clientCertPem = await readFile(clientCertPath, "utf8");
    const registerBody = JSON.stringify({
      client_id: CLIENT_ID,
      certificate: clientCertPem,
      allowed_scopes: SCOPE,
    });
    const registerResponse = await insecureRequest(
      "/clients/register",
      "POST",
      { "content-type": "application/json", "content-length": String(Buffer.byteLength(registerBody)) },
      registerBody,
    );
    // 409 (client_id já registrado) é tratado como sucesso: idempotente
    // entre execuções que reaproveitem o mesmo simulador de longa duração.
    if (![200, 201, 409].includes(registerResponse.status)) {
      throw new Error(
        `Falha ao registrar client de teste no simulador: HTTP ${registerResponse.status} — ${registerResponse.body}`,
      );
    }

    client = await createSmartTokenClient({
      fhirBase: SIMULATOR_FHIR_BASE,
      clientId: CLIENT_ID,
      privateKeyPem: clientKeyPath,
      certificatePem: clientCertPath,
      serverTrustAnchor: serverCertPath,
    });
  }, 60_000);

  afterAll(async () => {
    await client?.close();
    try {
      runHubsaude(["simulador", "stop"]);
    } catch {
      // já parado — nada a fazer
    }
    await rm(dir, { recursive: true, force: true });
  }, 30_000);

  it("obtém um access token real via mTLS, com o token endpoint resolvido por smart-configuration", async () => {
    const token = await client?.obtainToken(SCOPE);

    expect(typeof token).toBe("string");
    expect(token?.length).toBeGreaterThan(0);
  }, 30_000);
});
