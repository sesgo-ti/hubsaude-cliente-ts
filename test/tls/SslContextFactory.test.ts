import { execFileSync } from "node:child_process";
import { createPrivateKey } from "node:crypto";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import type { IncomingMessage } from "node:http";
import { createServer, request, type Agent, type Server } from "node:https";
import type { TLSSocket } from "node:tls";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { loadCertificate } from "../../src/signing/PemLoader.js";
import { buildAgent, checkCertificateValidity, DEFAULT_TLS_PROTOCOL } from "../../src/tls/SslContextFactory.js";

const PORT = 8543;
const HOST = "localhost";

let dir: string;
let server: Server | undefined;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "sslfactory-test-"));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

afterEach(async () => {
  if (server !== undefined) {
    await new Promise<void>((resolve) => server?.close(() => resolve()));
    server = undefined;
  }
});

function p(name: string): string {
  return join(dir, name);
}

function openssl(args: string[]): void {
  execFileSync("openssl", args, { stdio: "ignore" });
}

/** Faz um GET simples usando o `Agent` fornecido, devolvendo status e corpo. */
function getViaAgent(agent: Agent): Promise<{ status: number; body: string }> {
  return new Promise((resolve, reject) => {
    const req = request({ host: HOST, port: PORT, path: "/", method: "GET", agent }, (res: IncomingMessage) => {
      const chunks: Buffer[] = [];
      res.on("data", (chunk: Buffer) => chunks.push(chunk));
      res.on("end", () => resolve({ status: res.statusCode ?? 0, body: Buffer.concat(chunks).toString("utf8") }));
    });
    req.on("error", reject);
    req.end();
  });
}

/** Monta uma CA de teste + certificado de servidor assinado por ela. */
async function setupCaAndServer(): Promise<{ caPem: string; serverStarted: Promise<void> }> {
  openssl(["genrsa", "-out", p("ca-key.pem"), "2048"]);
  openssl(["req", "-x509", "-new", "-key", p("ca-key.pem"), "-out", p("ca-cert.pem"), "-days", "1", "-subj", "/CN=CA-Teste"]);
  openssl(["genrsa", "-out", p("server-key.pem"), "2048"]);
  openssl(["req", "-new", "-key", p("server-key.pem"), "-out", p("server.csr"), "-subj", "/CN=localhost"]);
  openssl(["x509", "-req", "-in", p("server.csr"), "-CA", p("ca-cert.pem"), "-CAkey", p("ca-key.pem"), "-CAcreateserial", "-out", p("server-cert.pem"), "-days", "1"]);

  const [serverKey, serverCert, caPem] = await Promise.all([
    readFile(p("server-key.pem")),
    readFile(p("server-cert.pem")),
    readFile(p("ca-cert.pem"), "utf8"),
  ]);

  return {
    caPem,
    serverStarted: new Promise<void>((resolve) => {
      server = createServer(
        { key: serverKey, cert: serverCert, ca: caPem, requestCert: true, rejectUnauthorized: true },
        (req, res) => {
          const cert = (req.socket as TLSSocket).getPeerCertificate();
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ clientCN: cert.subject?.CN ?? null }));
        },
      );
      server.listen(PORT, resolve);
    }),
  };
}

/** Gera um certificado de cliente assinado pela CA de teste. */
async function generateClientCert(commonName: string): Promise<{ keyPem: string; certPem: string }> {
  const keyPath = p(`${commonName}-key.pem`);
  const csrPath = p(`${commonName}.csr`);
  const certPath = p(`${commonName}-cert.pem`);
  openssl(["genrsa", "-out", keyPath, "2048"]);
  openssl(["req", "-new", "-key", keyPath, "-out", csrPath, "-subj", `/CN=${commonName}`]);
  openssl(["x509", "-req", "-in", csrPath, "-CA", p("ca-cert.pem"), "-CAkey", p("ca-key.pem"), "-CAcreateserial", "-out", certPath, "-days", "1"]);
  const [keyPem, certPem] = await Promise.all([readFile(keyPath, "utf8"), readFile(certPath, "utf8")]);
  return { keyPem, certPem };
}

describe("checkCertificateValidity", () => {
  it("não lança para certificado dentro da validade", async () => {
    openssl(["req", "-x509", "-newkey", "rsa:2048", "-keyout", p("valido-key.pem"), "-out", p("valido-cert.pem"), "-days", "1", "-nodes", "-subj", "/CN=valido"]);
    const cert = await loadCertificate(p("valido-cert.pem"));

    expect(() => checkCertificateValidity(cert, "<teste>")).not.toThrow();
  });
});

describe("buildAgent", () => {
  it("realiza mTLS com sucesso quando o certificado do cliente é confiável", async () => {
    const { caPem, serverStarted } = await setupCaAndServer();
    await serverStarted;
    const { keyPem, certPem } = await generateClientCert("cliente-confiavel");

    const agent = buildAgent({
      serverTrustAnchor: caPem,
      clientKey: createPrivateKey(keyPem),
      clientCertificate: certPem,
    });
    try {
      const { status, body } = await getViaAgent(agent);
      const parsed = JSON.parse(body) as { clientCN: string };
      expect(status).toBe(200);
      expect(parsed.clientCN).toBe("cliente-confiavel");
    } finally {
      agent.destroy();
    }
  });

  it("rejeita quando o certificado do cliente não é assinado pela CA esperada", async () => {
    const { caPem, serverStarted } = await setupCaAndServer();
    await serverStarted;
    // Chave/certificado autoassinados, não emitidos pela CA de teste.
    openssl(["req", "-x509", "-newkey", "rsa:2048", "-keyout", p("intruso-key.pem"), "-out", p("intruso-cert.pem"), "-days", "1", "-nodes", "-subj", "/CN=intruso"]);
    const keyPem = await readFile(p("intruso-key.pem"), "utf8");
    const certPem = await readFile(p("intruso-cert.pem"), "utf8");

    const agent = buildAgent({
      serverTrustAnchor: caPem,
      clientKey: createPrivateKey(keyPem),
      clientCertificate: certPem,
    });
    try {
      await expect(getViaAgent(agent)).rejects.toThrow();
    } finally {
      agent.destroy();
    }
  });

  it("funciona como TLS unidirecional sem material de cliente (retrocompatível)", async () => {
    const { caPem, serverStarted } = await setupCaAndServer();
    // Servidor não exige certificado nesta variação — reconfigura sem requestCert.
    if (server !== undefined) {
      await new Promise<void>((resolve) => server?.close(() => resolve()));
    }
    const [serverKey, serverCert] = await Promise.all([
      readFile(p("server-key.pem")),
      readFile(p("server-cert.pem")),
    ]);
    await new Promise<void>((resolve) => {
      server = createServer({ key: serverKey, cert: serverCert }, (_req, res) => {
        res.writeHead(200);
        res.end("ok");
      });
      server.listen(PORT, resolve);
    });

    const agent = buildAgent({ serverTrustAnchor: caPem });
    try {
      const { status } = await getViaAgent(agent);
      expect(status).toBe(200);
    } finally {
      agent.destroy();
    }
    void serverStarted; // apenas para gerar a CA/certs; o servidor real é o reconfigurado acima
  });

  it("lança Error quando clientPfx e clientKey/clientCertificate são fornecidos juntos", () => {
    expect(() =>
      buildAgent({
        clientPfx: Buffer.from("qualquer coisa"),
        clientKey: "chave qualquer, nunca chega a ser usada",
      }),
    ).toThrow("Defina clientPfx OU clientKey/clientCertificate");
  });

  it("usa TLSv1.3 como protocolo padrão", () => {
    expect(DEFAULT_TLS_PROTOCOL).toBe("TLSv1.3");
  });
});
