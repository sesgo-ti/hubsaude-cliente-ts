import { execFileSync, spawn } from "node:child_process";
import net from "node:net";
import { createServer as createHttpServer, get as httpGet, type IncomingMessage, type Server as HttpServer } from "node:http";
import { Agent as HttpsAgent, createServer as createHttpsServer, request as httpsRequest, type Server as HttpsServer } from "node:https";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { SmartTokenError } from "../../src/errors/SmartTokenError.js";
import {
  HTTP_TOO_MANY_REQUESTS,
  httpFailure,
  isClientSideCertificateValidationFailure,
  isConfirmedClientCertificateRejection,
  isLikelyClientCertificateRejection,
  isTransientNetworkFailure,
  sanitizeErrorResponse,
} from "../../src/resilience/ErrorClassifier.js";
import type { Logger } from "../../src/logging/Logger.js";

let dir: string;
let cleanupServer: (() => Promise<void>) | undefined;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "errorclassifier-test-"));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

afterEach(async () => {
  await cleanupServer?.();
  cleanupServer = undefined;
});

function p(name: string): string {
  return join(dir, name);
}

function openssl(args: string[]): void {
  execFileSync("openssl", args, { stdio: "ignore" });
}

async function captureError(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
    throw new Error("esperava que a Promise rejeitasse, mas ela resolveu");
  } catch (err) {
    return err;
  }
}

/** GET simples via `node:http`, devolvendo uma Promise que rejeita no erro do socket/requisição. */
function plainGet(url: string, signal?: AbortSignal): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    httpGet(url, { signal }, resolve).on("error", reject);
  });
}

/** GET simples via `node:https`, com `Agent` customizado (mTLS/CA), devolvendo uma Promise. */
function httpsGetWithAgent(url: string, agent: HttpsAgent): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    const req = httpsRequest(url, { agent }, resolve);
    req.on("error", reject);
    req.end();
  });
}

describe("isTransientNetworkFailure", () => {
  it("retorna true para conexão recusada (porta fechada)", async () => {
    const err = await captureError(plainGet("http://127.0.0.1:65530/"));
    expect(isTransientNetworkFailure(err)).toBe(true);
  });

  it("retorna true para timeout (AbortSignal.timeout)", async () => {
    const server = createHttpServer(() => {
      /* nunca responde */
    });
    await new Promise<void>((resolve) => server.listen(0, resolve));
    cleanupServer = () => new Promise<void>((resolve) => server.close(() => resolve()));
    const port = (server.address() as net.AddressInfo).port;

    const err = await captureError(plainGet(`http://127.0.0.1:${port}/`, AbortSignal.timeout(300)));
    expect(isTransientNetworkFailure(err)).toBe(true);
  });

  it("retorna true para conexão derrubada abruptamente", async () => {
    const server = net.createServer((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.listen(0, resolve));
    cleanupServer = () => new Promise<void>((resolve) => server.close(() => resolve()));
    const port = (server.address() as net.AddressInfo).port;

    const err = await captureError(plainGet(`http://127.0.0.1:${port}/`));
    expect(isTransientNetworkFailure(err)).toBe(true);
  });

  it("retorna false para host inexistente (DNS) — mesmo comportamento do Java (não é SocketException)", async () => {
    const err = await captureError(plainGet("http://host-invalido-de-teste.invalid/"));
    expect(isTransientNetworkFailure(err)).toBe(false);
  });

  it("retorna false quando o cliente rejeitou o certificado do servidor (não é falha de rede transitória)", async () => {
    openssl(["req", "-x509", "-newkey", "rsa:2048", "-keyout", p("s-key.pem"), "-out", p("s-cert.pem"), "-days", "1", "-nodes", "-subj", "/CN=localhost"]);
    openssl(["req", "-x509", "-newkey", "rsa:2048", "-keyout", p("outra-key.pem"), "-out", p("outra-cert.pem"), "-days", "1", "-nodes", "-subj", "/CN=outra"]);
    const [key, cert, wrongCa] = await Promise.all([
      readFile(p("s-key.pem")),
      readFile(p("s-cert.pem")),
      readFile(p("outra-cert.pem")),
    ]);
    const server: HttpsServer = createHttpsServer({ key, cert }, (_req, res) => res.end("ok"));
    await new Promise<void>((resolve) => server.listen(0, resolve));
    cleanupServer = () => new Promise<void>((resolve) => server.close(() => resolve()));
    const port = (server.address() as net.AddressInfo).port;

    const agent = new HttpsAgent({ ca: wrongCa });
    try {
      const err = await captureError(httpsGetWithAgent(`https://localhost:${port}/`, agent));
      expect(isClientSideCertificateValidationFailure(err)).toBe(true);
      expect(isTransientNetworkFailure(err)).toBe(false);
    } finally {
      agent.destroy();
    }
  });
});

describe("isConfirmedClientCertificateRejection", () => {
  let sServerPid: number | undefined;

  afterEach(() => {
    if (sServerPid !== undefined) {
      process.kill(sServerPid, "SIGTERM");
      sServerPid = undefined;
    }
  });

  /** Sobe um `openssl s_server` real, que envia alertas TLS de verdade ao rejeitar. */
  async function startRealAlertServer(port: number): Promise<{ caPem: Buffer }> {
    openssl(["genrsa", "-out", p("ca3-key.pem"), "2048"]);
    openssl(["req", "-x509", "-new", "-key", p("ca3-key.pem"), "-out", p("ca3-cert.pem"), "-days", "1", "-subj", "/CN=CA-Teste-3"]);
    openssl(["genrsa", "-out", p("s3-key.pem"), "2048"]);
    openssl(["req", "-new", "-key", p("s3-key.pem"), "-out", p("s3.csr"), "-subj", "/CN=localhost"]);
    openssl(["x509", "-req", "-in", p("s3.csr"), "-CA", p("ca3-cert.pem"), "-CAkey", p("ca3-key.pem"), "-CAcreateserial", "-out", p("s3-cert.pem"), "-days", "1"]);

    const proc = spawn(
      "openssl",
      [
        "s_server",
        "-accept",
        String(port),
        "-cert",
        p("s3-cert.pem"),
        "-key",
        p("s3-key.pem"),
        "-CAfile",
        p("ca3-cert.pem"),
        "-Verify",
        "1",
        "-verify_return_error",
        "-www",
      ],
      { stdio: "ignore" },
    );
    sServerPid = proc.pid;
    // Aguarda o s_server abrir a porta (sem um sinal de "pronto" explícito).
    await new Promise((resolve) => setTimeout(resolve, 500));

    return { caPem: await readFile(p("ca3-cert.pem")) };
  }

  it("retorna true quando o servidor envia um alerta TLS real de CA não confiável", async () => {
    const port = 18443;
    await startRealAlertServer(port);
    // Certificado de cliente autoassinado — não emitido pela CA que o servidor confia.
    openssl(["req", "-x509", "-newkey", "rsa:2048", "-keyout", p("intruso3-key.pem"), "-out", p("intruso3-cert.pem"), "-days", "1", "-nodes", "-subj", "/CN=intruso3"]);
    const [key, cert] = await Promise.all([readFile(p("intruso3-key.pem")), readFile(p("intruso3-cert.pem"))]);

    const agent = new HttpsAgent({ key, cert, rejectUnauthorized: false });
    try {
      const err = await captureError(httpsGetWithAgent(`https://localhost:${port}/`, agent));
      expect(isConfirmedClientCertificateRejection(err, true)).toBe(true);
      expect(isLikelyClientCertificateRejection(err, true)).toBe(false); // não é o caso ambíguo
    } finally {
      agent.destroy();
    }
  });

  it("retorna false quando mTLS não estava configurado, mesmo com alerta real", async () => {
    const port = 18444;
    await startRealAlertServer(port);
    openssl(["req", "-x509", "-newkey", "rsa:2048", "-keyout", p("intruso4-key.pem"), "-out", p("intruso4-cert.pem"), "-days", "1", "-nodes", "-subj", "/CN=intruso4"]);
    const [key, cert] = await Promise.all([readFile(p("intruso4-key.pem")), readFile(p("intruso4-cert.pem"))]);

    const agent = new HttpsAgent({ key, cert, rejectUnauthorized: false });
    try {
      const err = await captureError(httpsGetWithAgent(`https://localhost:${port}/`, agent));
      expect(isConfirmedClientCertificateRejection(err, false)).toBe(false);
    } finally {
      agent.destroy();
    }
  });
});

describe("isLikelyClientCertificateRejection", () => {
  it("retorna false quando mTLS não estava configurado", async () => {
    const err = await captureError(plainGet("http://127.0.0.1:65530/"));
    expect(isLikelyClientCertificateRejection(err, false)).toBe(false);
  });

  it("retorna false quando o erro é o cliente rejeitando o certificado do servidor", async () => {
    openssl(["req", "-x509", "-newkey", "rsa:2048", "-keyout", p("s2-key.pem"), "-out", p("s2-cert.pem"), "-days", "1", "-nodes", "-subj", "/CN=localhost"]);
    openssl(["req", "-x509", "-newkey", "rsa:2048", "-keyout", p("outra2-key.pem"), "-out", p("outra2-cert.pem"), "-days", "1", "-nodes", "-subj", "/CN=outra"]);
    const [key, cert, wrongCa] = await Promise.all([
      readFile(p("s2-key.pem")),
      readFile(p("s2-cert.pem")),
      readFile(p("outra2-cert.pem")),
    ]);
    const server: HttpsServer = createHttpsServer({ key, cert }, (_req, res) => res.end("ok"));
    await new Promise<void>((resolve) => server.listen(0, resolve));
    cleanupServer = () => new Promise<void>((resolve) => server.close(() => resolve()));
    const port = (server.address() as net.AddressInfo).port;

    const agent = new HttpsAgent({ ca: wrongCa });
    try {
      const err = await captureError(httpsGetWithAgent(`https://localhost:${port}/`, agent));
      expect(isLikelyClientCertificateRejection(err, true)).toBe(false);
    } finally {
      agent.destroy();
    }
  });

  it("retorna true (sugestão) quando mTLS estava configurado e a conexão caiu abruptamente", async () => {
    const server = net.createServer((socket) => socket.destroy());
    await new Promise<void>((resolve) => server.listen(0, resolve));
    cleanupServer = () => new Promise<void>((resolve) => server.close(() => resolve()));
    const port = (server.address() as net.AddressInfo).port;

    const err = await captureError(plainGet(`http://127.0.0.1:${port}/`));
    expect(isLikelyClientCertificateRejection(err, true)).toBe(true);
  });
});

describe("sanitizeErrorResponse", () => {
  it("redige access_token em JSON", () => {
    const result = sanitizeErrorResponse('{"access_token":"segredo-super-secreto","expires_in":60}');
    expect(result).not.toContain("segredo-super-secreto");
    expect(result).toContain("[REDACTED]");
  });

  it("redige token em form-urlencoded", () => {
    const result = sanitizeErrorResponse("error=invalid_grant&token=abc123&outro=valor");
    expect(result).not.toContain("abc123");
    expect(result).toContain("[REDACTED]");
  });

  it("trunca respostas longas para 500 caracteres, preservando a redação", () => {
    const longBody = `{"access_token":"segredo","padding":"${"x".repeat(1000)}"}`;
    const result = sanitizeErrorResponse(longBody);
    expect(result.length).toBeLessThanOrEqual(503); // 500 + "..."
    expect(result).not.toContain("segredo");
  });

  it("retorna <empty> para corpo ausente", () => {
    expect(sanitizeErrorResponse(null)).toBe("<empty>");
    expect(sanitizeErrorResponse(undefined)).toBe("<empty>");
    expect(sanitizeErrorResponse("")).toBe("<empty>");
  });
});

describe("httpFailure", () => {
  it("constrói SmartTokenError com status, traceId e corpo sanitizado", () => {
    const error = httpFailure(400, '{"error":"invalid_request"}', null, "abc123");

    expect(error).toBeInstanceOf(SmartTokenError);
    expect(error.message).toContain("HTTP 400");
    expect(error.message).toContain("traceId=abc123");
    expect(error.message).toContain("invalid_request");
  });

  it("inclui Retry-After na mensagem quando presente", () => {
    const error = httpFailure(HTTP_TOO_MANY_REQUESTS, "{}", "30", "abc123");

    expect(error.message).toContain("Retry-After: 30");
    expect(error.message).toContain("Rate limit atingido");
  });

  it("chama logger.warn para 429 e logger.error para os demais", () => {
    const calls: { level: string; message: string }[] = [];
    const logger: Logger = {
      warn: (message) => calls.push({ level: "warn", message }),
      error: (message) => calls.push({ level: "error", message }),
    };

    httpFailure(HTTP_TOO_MANY_REQUESTS, "{}", null, "t1", logger);
    httpFailure(500, "{}", null, "t2", logger);

    expect(calls).toEqual([
      { level: "warn", message: expect.stringContaining("429") },
      { level: "error", message: expect.stringContaining("500") },
    ]);
  });

  it("não lança quando nenhum logger é informado", () => {
    expect(() => httpFailure(500, "{}", null, "t1")).not.toThrow();
  });
});
