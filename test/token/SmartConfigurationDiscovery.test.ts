import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import { Agent } from "node:https";
import type { AddressInfo } from "node:net";

type Handler = (req: IncomingMessage, res: ServerResponse) => void;
import { afterEach, describe, expect, it } from "vitest";
import { SmartTokenError } from "../../src/errors/SmartTokenError.js";
import { discoverTokenEndpoint, requireHttps } from "../../src/token/SmartConfigurationDiscovery.js";

describe("requireHttps", () => {
  it("aceita https", () => {
    expect(() => requireHttps("https://hub.saude.go.gov.br/auth/token", "tokenEndpoint")).not.toThrow();
  });

  it("aceita http em localhost e 127.0.0.1", () => {
    expect(() => requireHttps("http://localhost:8080/token", "tokenEndpoint")).not.toThrow();
    expect(() => requireHttps("http://127.0.0.1:8080/token", "tokenEndpoint")).not.toThrow();
  });

  it("rejeita http fora de localhost", () => {
    expect(() => requireHttps("http://exemplo.com/token", "tokenEndpoint")).toThrow(RangeError);
  });

  it("rejeita URL inválida", () => {
    expect(() => requireHttps("não-é-uma-url", "tokenEndpoint")).toThrow(RangeError);
  });
});

describe("discoverTokenEndpoint", () => {
  let server: Server | undefined;
  const agent = new Agent();

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
    return `http://127.0.0.1:${port}`;
  }

  it("descobre o token_endpoint com sucesso", async () => {
    const base = await startServer((req, res) => {
      expect(req.url).toBe("/.well-known/smart-configuration");
      expect(req.headers.traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-00$/);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ token_endpoint: "https://localhost:9999/auth/token" }));
    });

    const endpoint = await discoverTokenEndpoint(base, agent, 5000);

    expect(endpoint).toBe("https://localhost:9999/auth/token");
  });

  it("trata corretamente a base com barra final", async () => {
    const base = await startServer((req, res) => {
      expect(req.url).toBe("/.well-known/smart-configuration");
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ token_endpoint: "https://localhost:9999/auth/token" }));
    });

    await expect(discoverTokenEndpoint(`${base}/`, agent, 5000)).resolves.toBe("https://localhost:9999/auth/token");
  });

  it("falha quando a resposta não é 200", async () => {
    const base = await startServer((_req, res) => {
      res.writeHead(500);
      res.end("erro interno");
    });

    await expect(discoverTokenEndpoint(base, agent, 5000)).rejects.toThrow(SmartTokenError);
  });

  it("falha quando a resposta não contém token_endpoint", async () => {
    const base = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ outra_coisa: true }));
    });

    await expect(discoverTokenEndpoint(base, agent, 5000)).rejects.toThrow(SmartTokenError);
  });

  it("falha quando o token_endpoint descoberto não usa https (fora de localhost)", async () => {
    const base = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ token_endpoint: "http://endpoint-inseguro.com/token" }));
    });

    await expect(discoverTokenEndpoint(base, agent, 5000)).rejects.toThrow(RangeError);
  });
});
