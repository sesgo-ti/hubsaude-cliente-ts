import { createServer, get, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;
import { afterEach, describe, expect, it } from "vitest";
import { SmartTokenError } from "../../src/errors/SmartTokenError.js";
import {
  DEFAULT_EXPIRES_IN_SECONDS,
  MAX_EXPIRES_IN_SECONDS,
  readBoundedText,
  sanitizeExpiresIn,
} from "../../src/token/TokenResponseGuard.js";

describe("sanitizeExpiresIn", () => {
  it("assume o padrão quando ausente", () => {
    expect(sanitizeExpiresIn({})).toBe(DEFAULT_EXPIRES_IN_SECONDS);
  });

  it("aceita um valor válido", () => {
    expect(sanitizeExpiresIn({ expires_in: 120 })).toBe(120);
  });

  it.each([0, -1, "abc", null])("rejeita expires_in inválido: %j", (value) => {
    expect(() => sanitizeExpiresIn({ expires_in: value })).toThrow(SmartTokenError);
  });

  it("normaliza para o teto quando acima do máximo", () => {
    expect(sanitizeExpiresIn({ expires_in: MAX_EXPIRES_IN_SECONDS + 1000 })).toBe(MAX_EXPIRES_IN_SECONDS);
  });

  it("trunca valores fracionários", () => {
    expect(sanitizeExpiresIn({ expires_in: 59.9 })).toBe(59);
  });
});

describe("readBoundedText", () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server !== undefined) {
      await new Promise<void>((resolve) => server?.close(() => resolve()));
      server = undefined;
    }
  });

  async function startServer(handler: Handler): Promise<string> {
    server = createServer(handler);
    await new Promise<void>((resolve) => server?.listen(0, resolve));
    const port = (server?.address() as AddressInfo).port;
    return `http://127.0.0.1:${port}/`;
  }

  /** Faz um GET simples e devolve o `IncomingMessage` cru (sem ler o corpo). */
  function getResponse(url: string): Promise<IncomingMessage> {
    return new Promise((resolve, reject) => {
      get(url, resolve).on("error", reject);
    });
  }

  it("lê o corpo normalmente quando dentro do limite", async () => {
    const url = await startServer((_req, res) => res.end("corpo pequeno"));
    const response = await getResponse(url);

    expect(await readBoundedText(response, 1024)).toBe("corpo pequeno");
  });

  it("rejeita de imediato quando Content-Length declarado excede o limite", async () => {
    const url = await startServer((_req, res) => {
      res.writeHead(200, { "Content-Length": "10000" });
      res.end("x".repeat(10000));
    });
    const response = await getResponse(url);

    await expect(readBoundedText(response, 100)).rejects.toThrow(SmartTokenError);
  });

  it("aborta a leitura ao ultrapassar o limite sem Content-Length (chunked)", async () => {
    const url = await startServer((_req, res) => {
      res.writeHead(200);
      // Sem Content-Length: força modo chunked, sem tamanho declarado.
      for (let i = 0; i < 100; i++) {
        res.write("x".repeat(1000));
      }
      res.end();
    });
    const response = await getResponse(url);

    await expect(readBoundedText(response, 500)).rejects.toThrow(SmartTokenError);
  });
});
