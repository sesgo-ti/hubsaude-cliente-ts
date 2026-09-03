import { execFileSync, spawn, type ChildProcess } from "node:child_process";
import { generateKeyPairSync, verify } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import { SmartTokenError } from "../../src/errors/SmartTokenError.js";
import { createSmartTokenClient, SmartTokenClient } from "../../src/client/SmartTokenClient.js";

let dir: string;
let server: Server | undefined;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "smarttokenclient-test-"));
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

type Handler = (req: IncomingMessage, res: ServerResponse, body: string) => void;

async function startServer(handler: Handler): Promise<string> {
  server = createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => handler(req, res, Buffer.concat(chunks).toString("utf8")));
  });
  await new Promise<void>((resolve) => server?.listen(0, resolve));
  const port = (server?.address() as AddressInfo).port;
  return `http://127.0.0.1:${port}`;
}

interface DecodedAssertion {
  header: Record<string, unknown>;
  claims: Record<string, unknown>;
  signatureValid: boolean;
}

/** JWT sempre tem 3 partes; ajuda o TS (`noUncheckedIndexedAccess`) a saber disso. */
function jwtPart(jwt: string, index: 0 | 1 | 2): string {
  const part = jwt.split(".")[index];
  if (part === undefined) {
    throw new Error(`JWT mal formado, faltando a parte ${index}: ${jwt}`);
  }
  return part;
}

function decodeAndVerifyAssertion(assertion: string, publicKeyPem: string): DecodedAssertion {
  const headerB64 = jwtPart(assertion, 0);
  const payloadB64 = jwtPart(assertion, 1);
  const signatureB64 = jwtPart(assertion, 2);
  const header = JSON.parse(Buffer.from(headerB64, "base64url").toString("utf8"));
  const claims = JSON.parse(Buffer.from(payloadB64, "base64url").toString("utf8"));
  const signature = Buffer.from(signatureB64, "base64url");
  const signatureValid = verify("sha384", Buffer.from(`${headerB64}.${payloadB64}`), publicKeyPem, signature);
  return { header, claims, signatureValid };
}

async function generateRsaKeyFile(): Promise<{ path: string; publicKeyPem: string }> {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  const path = p(`key-${Date.now()}-${Math.random()}.pem`);
  await writeFile(path, privateKey as unknown as string);
  return { path, publicKeyPem: publicKey as unknown as string };
}

describe("createSmartTokenClient — validações de configuração (RF-18)", () => {
  it("falha quando tokenEndpoint e fhirBase são ambos definidos", async () => {
    await expect(
      createSmartTokenClient({
        tokenEndpoint: "https://a/token",
        fhirBase: "https://a",
        clientId: "c",
        privateKeyPem: "/tmp/nao-importa.pem",
      }),
    ).rejects.toThrow(Error);
  });

  it("falha quando nenhum dos dois é definido", async () => {
    await expect(createSmartTokenClient({ clientId: "c", privateKeyPem: "/tmp/x.pem" })).rejects.toThrow(Error);
  });

  it("falha quando clientId está ausente", async () => {
    await expect(
      createSmartTokenClient({ tokenEndpoint: "https://a/token", privateKeyPem: "/tmp/x.pem" } as never),
    ).rejects.toThrow(Error);
  });

  it("falha quando signingStrategy e privateKeyPem são ambos definidos", async () => {
    await expect(
      createSmartTokenClient({
        tokenEndpoint: "https://a/token",
        clientId: "c",
        privateKeyPem: "/tmp/x.pem",
        signingStrategy: () => new Uint8Array(),
      }),
    ).rejects.toThrow(Error);
  });

  it("falha quando nem signingStrategy nem privateKeyPem são definidos", async () => {
    await expect(
      createSmartTokenClient({
        tokenEndpoint: "https://a/token",
        clientId: "c",
      } as never),
    ).rejects.toThrow(Error);
  });

  it("falha quando tokenCacheMaxEntries não é positivo", async () => {
    const { path } = await generateRsaKeyFile();
    await expect(
      createSmartTokenClient({
        tokenEndpoint: "https://a/token",
        clientId: "c",
        privateKeyPem: path,
        tokenCacheMaxEntries: 0,
      }),
    ).rejects.toThrow(RangeError);
  });

  it("falha quando o algoritmo JWT não é reconhecido", async () => {
    const { path } = await generateRsaKeyFile();
    await expect(
      createSmartTokenClient({
        tokenEndpoint: "https://a/token",
        clientId: "c",
        privateKeyPem: path,
        jwtAlgorithm: "HS256",
      }),
    ).rejects.toThrow(SmartTokenError);
  });

  it("falha quando hubContext é inválido", async () => {
    const { path } = await generateRsaKeyFile();
    await expect(
      createSmartTokenClient({
        tokenEndpoint: "https://a/token",
        clientId: "c",
        privateKeyPem: path,
        hubContext: { ig: "IG-Invalido", versao: "0.0.1" },
      }),
    ).rejects.toThrow(RangeError);
  });

  it("falha quando tokenEndpoint não usa https fora de localhost", async () => {
    const { path } = await generateRsaKeyFile();
    await expect(
      createSmartTokenClient({
        tokenEndpoint: "http://exemplo.com/token",
        clientId: "c",
        privateKeyPem: path,
      }),
    ).rejects.toThrow(RangeError);
  });
});

describe("createSmartTokenClient + obtainToken — fluxo completo", () => {
  it("monta, assina e envia o client_assertion corretamente; servidor valida a assinatura", async () => {
    const { path, publicKeyPem } = await generateRsaKeyFile();
    let receivedBody: string | undefined;

    const base = await startServer((req, res, body) => {
      receivedBody = body;
      expect(req.headers["content-type"]).toBe("application/x-www-form-urlencoded");
      expect(req.headers.traceparent).toMatch(/^00-[0-9a-f]{32}-[0-9a-f]{16}-00$/);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "token-abc", expires_in: 120 }));
    });

    const client = await createSmartTokenClient({
      tokenEndpoint: `${base}/token`,
      clientId: "meu-cliente",
      privateKeyPem: path,
    });
    try {
      const token = await client.obtainToken("system/Patient.rs");
      expect(token).toBe("token-abc");

      const params = new URLSearchParams(receivedBody);
      expect(params.get("grant_type")).toBe("client_credentials");
      expect(params.get("client_id")).toBe("meu-cliente");
      expect(params.get("client_assertion_type")).toBe(
        "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
      );
      expect(params.get("scope")).toBe("system/Patient.rs");

      const assertion = params.get("client_assertion");
      expect(assertion).not.toBeNull();
      // RF-01.1: 3 partes Base64URL SEM padding (nada de "=" nas partes).
      expect((assertion as string).split(".")).toHaveLength(3);
      expect(assertion).not.toContain("=");
      const { header, claims, signatureValid } = decodeAndVerifyAssertion(assertion as string, publicKeyPem);

      expect(signatureValid).toBe(true);
      expect(header.alg).toBe("RS384");
      expect(header.typ).toBe("JWT");
      expect(header.kid).toBeUndefined();
      expect(claims.iss).toBe("meu-cliente");
      expect(claims.sub).toBe("meu-cliente");
      expect(claims.aud).toBe(`${base}/token`);
      expect(typeof claims.jti).toBe("string");
      expect((claims.exp as number) - (claims.iat as number)).toBe(60);
    } finally {
      await client.close();
    }
  });

  it("gera um jti diferente a cada requisição real", async () => {
    const { path } = await generateRsaKeyFile();
    const seenJtis: string[] = [];
    const base = await startServer((_req, res, body) => {
      const assertion = new URLSearchParams(body).get("client_assertion") ?? "";
      const claims = JSON.parse(Buffer.from(jwtPart(assertion, 1), "base64url").toString("utf8"));
      seenJtis.push(claims.jti);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "t", expires_in: 60 }));
    });

    const client = await createSmartTokenClient({
      tokenEndpoint: `${base}/token`,
      clientId: "c",
      privateKeyPem: path,
      enableTokenCache: false, // força duas requisições reais ao servidor
    });
    try {
      await client.obtainToken();
      await client.obtainToken();

      expect(seenJtis).toHaveLength(2);
      expect(seenJtis[0]).not.toBe(seenJtis[1]);
    } finally {
      await client.close();
    }
  });

  it("inclui kid no header quando keyId é configurado", async () => {
    const { path } = await generateRsaKeyFile();
    let receivedAssertion = "";
    const base = await startServer((_req, res, body) => {
      receivedAssertion = new URLSearchParams(body).get("client_assertion") ?? "";
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "t", expires_in: 60 }));
    });

    const client = await createSmartTokenClient({
      tokenEndpoint: `${base}/token`,
      clientId: "c",
      privateKeyPem: path,
      keyId: "minha-chave-2026",
    });
    try {
      await client.obtainToken();
      const header = JSON.parse(Buffer.from(jwtPart(receivedAssertion, 0), "base64url").toString("utf8"));
      expect(header.kid).toBe("minha-chave-2026");
    } finally {
      await client.close();
    }
  });

  it("inclui hub_ctx no payload quando configurado", async () => {
    const { path } = await generateRsaKeyFile();
    let receivedAssertion = "";
    const base = await startServer((_req, res, body) => {
      receivedAssertion = new URLSearchParams(body).get("client_assertion") ?? "";
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "t", expires_in: 60 }));
    });

    const client = await createSmartTokenClient({
      tokenEndpoint: `${base}/token`,
      clientId: "c",
      privateKeyPem: path,
      hubContext: { ig: "hemograma", versao: "0.0.1" },
    });
    try {
      await client.obtainToken();
      const claims = JSON.parse(Buffer.from(jwtPart(receivedAssertion, 1), "base64url").toString("utf8"));
      expect(claims.hub_ctx).toEqual({ ig: "hemograma", versao: "0.0.1" });
    } finally {
      await client.close();
    }
  });

  it("omite scope do form body quando não informado", async () => {
    const { path } = await generateRsaKeyFile();
    let receivedBody = "";
    const base = await startServer((_req, res, body) => {
      receivedBody = body;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "t", expires_in: 60 }));
    });

    const client = await createSmartTokenClient({ tokenEndpoint: `${base}/token`, clientId: "c", privateKeyPem: path });
    try {
      await client.obtainToken();
      expect(new URLSearchParams(receivedBody).has("scope")).toBe(false);
    } finally {
      await client.close();
    }
  });

  it("omite scope do form body quando é string vazia ou só espaços", async () => {
    const { path } = await generateRsaKeyFile();
    const receivedBodies: string[] = [];
    const base = await startServer((_req, res, body) => {
      receivedBodies.push(body);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "t", expires_in: 60 }));
    });

    const client = await createSmartTokenClient({
      tokenEndpoint: `${base}/token`,
      clientId: "c",
      privateKeyPem: path,
      enableTokenCache: false,
    });
    try {
      await client.obtainToken("");
      await client.obtainToken("   ");
      for (const body of receivedBodies) {
        expect(new URLSearchParams(body).has("scope")).toBe(false);
      }
    } finally {
      await client.close();
    }
  });

  it("reutiliza o token em cache em chamadas subsequentes para o mesmo scope", async () => {
    const { path } = await generateRsaKeyFile();
    let requestCount = 0;
    const base = await startServer((_req, res) => {
      requestCount++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: `token-${requestCount}`, expires_in: 3600 }));
    });

    const client = await createSmartTokenClient({ tokenEndpoint: `${base}/token`, clientId: "c", privateKeyPem: path });
    try {
      const first = await client.obtainToken("system/Patient.rs");
      const second = await client.obtainToken("system/Patient.rs");

      expect(first).toBe(second);
      expect(requestCount).toBe(1);
    } finally {
      await client.close();
    }
  });

  it("normaliza o scope (trim) antes de indexar o cache", async () => {
    const { path } = await generateRsaKeyFile();
    let requestCount = 0;
    const base = await startServer((_req, res) => {
      requestCount++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: `token-${requestCount}`, expires_in: 3600 }));
    });

    const client = await createSmartTokenClient({ tokenEndpoint: `${base}/token`, clientId: "c", privateKeyPem: path });
    try {
      const first = await client.obtainToken("  system/Patient.rs  ");
      const second = await client.obtainToken("system/Patient.rs");

      expect(first).toBe(second);
      expect(requestCount).toBe(1); // mesma entrada de cache, apesar dos espaços
    } finally {
      await client.close();
    }
  });

  it("N chamadas concorrentes do mesmo scope disparam 1 única requisição ao servidor (single-flight)", async () => {
    const { path } = await generateRsaKeyFile();
    let requestCount = 0;
    const base = await startServer((_req, res) => {
      requestCount++;
      // Resposta um pouco atrasada, pra garantir que as chamadas concorrentes
      // realmente se sobrepõem antes de qualquer uma terminar.
      setTimeout(() => {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ access_token: "token-unico", expires_in: 60 }));
      }, 20);
    });

    const client = await createSmartTokenClient({ tokenEndpoint: `${base}/token`, clientId: "c", privateKeyPem: path });
    try {
      const results = await Promise.all([
        client.obtainToken("system/Patient.rs"),
        client.obtainToken("system/Patient.rs"),
        client.obtainToken("system/Patient.rs"),
        client.obtainToken("system/Patient.rs"),
        client.obtainToken("system/Patient.rs"),
      ]);

      expect(results.every((token) => token === "token-unico")).toBe(true);
      expect(requestCount).toBe(1);
    } finally {
      await client.close();
    }
  });

  it("busca de novo após invalidateCache", async () => {
    const { path } = await generateRsaKeyFile();
    let requestCount = 0;
    const base = await startServer((_req, res) => {
      requestCount++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: `token-${requestCount}`, expires_in: 3600 }));
    });

    const client = await createSmartTokenClient({ tokenEndpoint: `${base}/token`, clientId: "c", privateKeyPem: path });
    try {
      await client.obtainToken();
      client.invalidateCache();
      await client.obtainToken();

      expect(requestCount).toBe(2);
    } finally {
      await client.close();
    }
  });

  it("busca de novo após invalidateCache(scope), preservando o cache de outros scopes", async () => {
    const { path } = await generateRsaKeyFile();
    let requestCount = 0;
    const base = await startServer((_req, res) => {
      requestCount++;
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: `token-${requestCount}`, expires_in: 3600 }));
    });

    const client = await createSmartTokenClient({ tokenEndpoint: `${base}/token`, clientId: "c", privateKeyPem: path });
    try {
      await client.obtainToken("system/Patient.rs");
      await client.obtainToken("system/Observation.rs");
      expect(requestCount).toBe(2);

      client.invalidateCache("system/Patient.rs");
      await client.obtainToken("system/Patient.rs"); // busca de novo
      await client.obtainToken("system/Observation.rs"); // continua em cache

      expect(requestCount).toBe(3);
    } finally {
      await client.close();
    }
  });

  it("obtainTokenResponse expõe o rawJson numa requisição real, e null quando vem do cache", async () => {
    const { path } = await generateRsaKeyFile();
    const base = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "t", expires_in: 3600 }));
    });

    const client = await createSmartTokenClient({ tokenEndpoint: `${base}/token`, clientId: "c", privateKeyPem: path });
    try {
      const first = await client.obtainTokenResponse();
      const second = await client.obtainTokenResponse();

      expect(first.rawJson).not.toBeNull();
      expect(second.rawJson).toBeNull();
    } finally {
      await client.close();
    }
  });

  it("HTTP diferente de 200 falha imediatamente, sem retry", async () => {
    const { path } = await generateRsaKeyFile();
    let requestCount = 0;
    const base = await startServer((_req, res) => {
      requestCount++;
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "invalid_grant" }));
    });

    const client = await SmartTokenClient.create(
      {
        tokenEndpoint: `${base}/token`,
        clientId: "c",
        privateKeyPem: path,
        maxRetries: 3,
      },
      async () => undefined,
    );
    try {
      await expect(client.obtainToken()).rejects.toThrow(SmartTokenError);
      expect(requestCount).toBe(1);
    } finally {
      await client.close();
    }
  });

  it("HTTP 429 falha imediatamente, sem retry (RF-03.3)", async () => {
    const { path } = await generateRsaKeyFile();
    let requestCount = 0;
    const base = await startServer((_req, res) => {
      requestCount++;
      res.writeHead(429, { "content-type": "application/json", "retry-after": "30" });
      res.end(JSON.stringify({ error: "rate_limited" }));
    });

    const client = await SmartTokenClient.create(
      {
        tokenEndpoint: `${base}/token`,
        clientId: "c",
        privateKeyPem: path,
        maxRetries: 3,
      },
      async () => undefined,
    );
    try {
      await expect(client.obtainToken()).rejects.toThrow(SmartTokenError);
      expect(requestCount).toBe(1);
    } finally {
      await client.close();
    }
  });

  it("200 sem access_token no corpo resulta em erro", async () => {
    const { path } = await generateRsaKeyFile();
    const base = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ token_type: "Bearer", expires_in: 60 })); // sem access_token
    });

    const client = await SmartTokenClient.create(
      {
        tokenEndpoint: `${base}/token`,
        clientId: "c",
        privateKeyPem: path,
      },
      async () => undefined,
    );
    try {
      await expect(client.obtainToken()).rejects.toThrow(SmartTokenError);
    } finally {
      await client.close();
    }
  });

  it("ignora campos desconhecidos na resposta de sucesso", async () => {
    const { path } = await generateRsaKeyFile();
    const base = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(
        JSON.stringify({
          access_token: "t",
          expires_in: 60,
          token_type: "Bearer",
          scope: "system/Patient.rs",
          campo_totalmente_desconhecido: { aninhado: [1, 2, 3] },
        }),
      );
    });

    const client = await createSmartTokenClient({ tokenEndpoint: `${base}/token`, clientId: "c", privateKeyPem: path });
    try {
      const token = await client.obtainToken();
      expect(token).toBe("t");
    } finally {
      await client.close();
    }
  });

  it("tenta de novo em falha transitória e obtém sucesso na 2ª tentativa", async () => {
    const { path } = await generateRsaKeyFile();
    let attempts = 0;
    const base = await startServer((_req, res) => {
      attempts++;
      if (attempts === 1) {
        res.destroy(); // simula queda de conexão na 1ª tentativa
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "token-recuperado", expires_in: 60 }));
    });

    const sleeps: number[] = [];
    const client = await SmartTokenClient.create(
      {
        tokenEndpoint: `${base}/token`,
        clientId: "c",
        privateKeyPem: path,
      },
      async (ms) => {
        sleeps.push(ms);
      },
    );
    try {
      const token = await client.obtainToken();
      expect(token).toBe("token-recuperado");
      expect(attempts).toBe(2);
      expect(sleeps).toEqual([1000]);
    } finally {
      await client.close();
    }
  });

  it("esgota as tentativas e falha com mensagem contendo o traceId", async () => {
    const { path } = await generateRsaKeyFile();
    const base = await startServer((_req, res) => res.destroy());

    const client = await SmartTokenClient.create(
      {
        tokenEndpoint: `${base}/token`,
        clientId: "c",
        privateKeyPem: path,
        maxRetries: 2,
      },
      async () => undefined,
    );
    try {
      await expect(client.obtainToken()).rejects.toThrow(/traceId=/);
    } finally {
      await client.close();
    }
  });

  it("aplica o backoff exponencial completo (1s, depois 2s) em duas falhas seguidas", async () => {
    const { path } = await generateRsaKeyFile();
    let attempts = 0;
    const base = await startServer((_req, res) => {
      attempts++;
      if (attempts <= 2) {
        res.destroy();
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "token-na-3a-tentativa", expires_in: 60 }));
    });

    const sleeps: number[] = [];
    const client = await SmartTokenClient.create(
      {
        tokenEndpoint: `${base}/token`,
        clientId: "c",
        privateKeyPem: path,
        maxRetries: 3,
      },
      async (ms) => {
        sleeps.push(ms);
      },
    );
    try {
      const token = await client.obtainToken();
      expect(token).toBe("token-na-3a-tentativa");
      expect(attempts).toBe(3);
      expect(sleeps).toEqual([1000, 2000]);
    } finally {
      await client.close();
    }
  });

  it("descobre o token endpoint via fhirBase", async () => {
    const { path } = await generateRsaKeyFile();
    const base = await startServer((req, res) => {
      if (req.url === "/.well-known/smart-configuration") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ token_endpoint: `${base}/auth/token` }));
        return;
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "t-via-discovery", expires_in: 60 }));
    });

    const client = await createSmartTokenClient({ fhirBase: base, clientId: "c", privateKeyPem: path });
    try {
      expect(client.getTokenEndpoint()).toBe(`${base}/auth/token`);
      const token = await client.obtainToken();
      expect(token).toBe("t-via-discovery");
    } finally {
      await client.close();
    }
  });

  it("close() é idempotente e rejeita novas operações depois de fechado", async () => {
    const { path } = await generateRsaKeyFile();
    const base = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "t", expires_in: 60 }));
    });

    const client = await createSmartTokenClient({ tokenEndpoint: `${base}/token`, clientId: "c", privateKeyPem: path });
    await client.close();
    await expect(client.close()).resolves.toBeUndefined(); // idempotente
    await expect(client.obtainToken()).rejects.toThrow(Error);
  });

  it("getJwtAlgorithm reflete o algoritmo configurado", async () => {
    const { path } = await generateRsaKeyFile();
    const base = await startServer((_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "t", expires_in: 60 }));
    });

    const client = await createSmartTokenClient({
      tokenEndpoint: `${base}/token`,
      clientId: "c",
      privateKeyPem: path,
      jwtAlgorithm: "rs256",
    });
    try {
      expect(client.getJwtAlgorithm()).toBe("rs256");
    } finally {
      await client.close();
    }
  });
});

describe("createSmartTokenClient — mTLS com consistência chave-certificado", () => {
  it("rejeita a construção quando a chave e o certificado não formam um par (RF-15)", async () => {
    const { path: key1 } = await generateRsaKeyFile();
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "rsa:2048", "-keyout", p("outra-key.pem"), "-out", p("cert-nao-relacionado.pem"), "-days", "1", "-nodes", "-subj", "/CN=outro"],
      { stdio: "ignore" },
    );

    await expect(
      createSmartTokenClient({
        tokenEndpoint: "https://localhost:9999/token",
        clientId: "c",
        privateKeyPem: key1,
        certificatePem: p("cert-nao-relacionado.pem"),
      }),
    ).rejects.toThrow(SmartTokenError);
  });

  it("aceita a construção quando a chave e o certificado formam um par válido", async () => {
    const keyPath = p("par-key.pem");
    const certPath = p("par-cert.pem");
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes", "-subj", "/CN=par-valido"],
      { stdio: "ignore" },
    );

    const client = await createSmartTokenClient({
      tokenEndpoint: "https://localhost:9999/token",
      clientId: "c",
      privateKeyPem: keyPath,
      certificatePem: certPath,
    });
    await client.close();
  });
});

describe("createSmartTokenClient — integração TLS/mTLS de ponta a ponta (§11.15)", () => {
  function opensslCa(prefix: string, cn: string): { keyPath: string; certPath: string } {
    const keyPath = p(`${prefix}-key.pem`);
    const certPath = p(`${prefix}-cert.pem`);
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes", "-subj", `/CN=${cn}`],
      { stdio: "ignore" },
    );
    return { keyPath, certPath };
  }

  /**
   * Sobe um `openssl s_server` real (não um `https.Server` do Node) —
   * necessário para o teste de RF-08.1 abaixo: só um servidor TLS que
   * segue a especificação à risca envia um alerta fatal explícito ao
   * rejeitar o certificado de cliente; o `https.Server` do Node apenas
   * derruba a conexão sem alerta (ver nota técnica em RASTREABILIDADE.md).
   */
  function spawnRealAlertServer(port: number, certPath: string, keyPath: string, caCertPath: string): ChildProcess {
    return spawn(
      "openssl",
      [
        "s_server",
        "-accept",
        String(port),
        "-cert",
        certPath,
        "-key",
        keyPath,
        "-CAfile",
        caCertPath,
        "-Verify",
        "1",
        "-verify_return_error",
        "-www",
      ],
      { stdio: "ignore" },
    );
  }

  function opensslSignedBy(prefix: string, cn: string, caKeyPath: string, caCertPath: string): { keyPath: string; certPath: string } {
    const keyPath = p(`${prefix}-key.pem`);
    const csrPath = p(`${prefix}.csr`);
    const certPath = p(`${prefix}-cert.pem`);
    execFileSync("openssl", ["genrsa", "-out", keyPath, "2048"], { stdio: "ignore" });
    execFileSync("openssl", ["req", "-new", "-key", keyPath, "-out", csrPath, "-subj", `/CN=${cn}`], { stdio: "ignore" });
    execFileSync(
      "openssl",
      ["x509", "-req", "-in", csrPath, "-CA", caCertPath, "-CAkey", caKeyPath, "-CAcreateserial", "-out", certPath, "-days", "1"],
      { stdio: "ignore" },
    );
    return { keyPath, certPath };
  }

  it("obtém um token de verdade sobre mTLS real + trust anchor customizado, via createSmartTokenClient", async () => {
    const ca = opensslCa("e2e-ca", "CA-Teste-E2E");
    const server = opensslSignedBy("e2e-server", "localhost", ca.keyPath, ca.certPath);
    const client_ = opensslSignedBy("e2e-client", "cliente-e2e", ca.keyPath, ca.certPath);

    const [serverKey, serverCert, caCertPem] = await Promise.all([
      readFile(server.keyPath),
      readFile(server.certPath),
      readFile(ca.certPath, "utf8"),
    ]);

    const { createServer: createHttpsServer } = await import("node:https");
    let receivedClientCN: string | undefined;
    const httpsServer = createHttpsServer(
      { key: serverKey, cert: serverCert, ca: caCertPem, requestCert: true, rejectUnauthorized: true },
      (req, res) => {
        const socket = req.socket as unknown as { getPeerCertificate(): { subject?: { CN?: string } } };
        receivedClientCN = socket.getPeerCertificate().subject?.CN;
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ access_token: "token-mtls-e2e", expires_in: 60 }));
      },
    );
    await new Promise<void>((resolve) => httpsServer.listen(0, resolve));
    const port = (httpsServer.address() as AddressInfo).port;

    const sdk = await createSmartTokenClient({
      tokenEndpoint: `https://localhost:${port}/token`,
      clientId: "c",
      privateKeyPem: client_.keyPath,
      certificatePem: client_.certPath,
      serverTrustAnchor: ca.certPath,
    });
    try {
      const token = await sdk.obtainToken();
      expect(token).toBe("token-mtls-e2e");
      expect(receivedClientCN).toBe("cliente-e2e");
    } finally {
      await sdk.close();
      await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
    }
  });

  it("valida o servidor com serverTrustAnchor mesmo sem mTLS (TLS unidirecional)", async () => {
    const ca = opensslCa("uni-ca", "CA-Uni");
    const server = opensslSignedBy("uni-server", "localhost", ca.keyPath, ca.certPath);
    const [serverKey, serverCert] = await Promise.all([readFile(server.keyPath), readFile(server.certPath)]);

    const { createServer: createHttpsServer } = await import("node:https");
    const httpsServer = createHttpsServer({ key: serverKey, cert: serverCert }, (_req, res) => {
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ access_token: "token-tls-simples", expires_in: 60 }));
    });
    await new Promise<void>((resolve) => httpsServer.listen(0, resolve));
    const port = (httpsServer.address() as AddressInfo).port;

    const { path } = await generateRsaKeyFile();
    const sdk = await createSmartTokenClient({
      tokenEndpoint: `https://localhost:${port}/token`,
      clientId: "c",
      privateKeyPem: path,
      serverTrustAnchor: ca.certPath,
    });
    try {
      const token = await sdk.obtainToken();
      expect(token).toBe("token-tls-simples");
    } finally {
      await sdk.close();
      await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
    }
  });

  it("rejeita a conexão quando o servidor NÃO é assinado pelo trust anchor configurado", async () => {
    const ca = opensslCa("rej-ca", "CA-Rejeitada");
    const outraCa = opensslCa("rej-outra-ca", "CA-Nao-Confiavel");
    const server = opensslSignedBy("rej-server", "localhost", outraCa.keyPath, outraCa.certPath);
    const [serverKey, serverCert] = await Promise.all([readFile(server.keyPath), readFile(server.certPath)]);

    const { createServer: createHttpsServer } = await import("node:https");
    const httpsServer = createHttpsServer({ key: serverKey, cert: serverCert }, (_req, res) => res.end("ok"));
    await new Promise<void>((resolve) => httpsServer.listen(0, resolve));
    const port = (httpsServer.address() as AddressInfo).port;

    const { path } = await generateRsaKeyFile();
    const sdk = await createSmartTokenClient({
      tokenEndpoint: `https://localhost:${port}/token`,
      clientId: "c",
      privateKeyPem: path,
      serverTrustAnchor: ca.certPath, // CA diferente da que assinou o servidor
      maxRetries: 1,
    });
    try {
      await expect(sdk.obtainToken()).rejects.toThrow();
    } finally {
      await sdk.close();
      await new Promise<void>((resolve) => httpsServer.close(() => resolve()));
    }
  });

  it("RF-08: inclui a dica de possível rejeição de certificado mTLS na mensagem final", async () => {
    const ca = opensslCa("rf08-ca", "CA-RF08");
    const client_ = opensslSignedBy("rf08-client", "cliente-rf08", ca.keyPath, ca.certPath);

    // Servidor que aceita a conexão TCP mas sempre derruba abruptamente —
    // o mesmo sinal ambíguo (UND_ERR_SOCKET) que uma rejeição de
    // certificado de cliente produziria (ver ErrorClassifier).
    const dropServer = createServer((_req, res) => res.destroy());
    await new Promise<void>((resolve) => dropServer.listen(0, resolve));
    const port = (dropServer.address() as AddressInfo).port;

    const sdk = await SmartTokenClient.create(
      {
        tokenEndpoint: `http://127.0.0.1:${port}/token`,
        clientId: "c",
        privateKeyPem: client_.keyPath,
        certificatePem: client_.certPath,
        maxRetries: 2,
      },
      async () => undefined,
    );
    try {
      await expect(sdk.obtainToken()).rejects.toThrow(/certificado de cliente rejeitado/);
    } finally {
      await sdk.close();
      await new Promise<void>((resolve) => dropServer.close(() => resolve()));
    }
  });

  it("RF-08.1: falha imediata, sem retry, quando o servidor envia um alerta TLS real de certificado (detecção confirmada)", async () => {
    const ca = opensslCa("rf08c-ca", "CA-RF08-Confirmado");
    const server = opensslSignedBy("rf08c-server", "localhost", ca.keyPath, ca.certPath);
    // Certificado de cliente autoassinado — NÃO emitido pela CA que o
    // servidor de teste (openssl s_server) confia. Diferente do teste
    // acima (que usa um servidor Node.js, que só derruba a conexão sem
    // alerta), aqui um servidor TLS real envia um alerta fatal
    // específico de certificado — confirmado empiricamente durante o
    // desenvolvimento desta detecção (ver RASTREABILIDADE.md).
    const intruso = opensslCa("rf08c-intruso", "intruso-rf08c");

    const port = 18545;
    const proc = spawnRealAlertServer(port, server.certPath, server.keyPath, ca.certPath);
    await new Promise((resolve) => setTimeout(resolve, 500));

    let sleepCalled = false;
    try {
      const sdk = await SmartTokenClient.create(
        {
          tokenEndpoint: `https://localhost:${port}/token`,
          clientId: "c",
          privateKeyPem: intruso.keyPath,
          certificatePem: intruso.certPath,
          serverTrustAnchor: ca.certPath,
          maxRetries: 5,
        },
        async () => {
          sleepCalled = true;
        },
      );
      try {
        await expect(sdk.obtainToken()).rejects.toThrow(/rejeitou o certificado de cliente.*sem novas tentativas/i);
        expect(sleepCalled).toBe(false); // RF-08.1: nenhum backoff/retry deve ter ocorrido
      } finally {
        await sdk.close();
      }
    } finally {
      proc.kill("SIGTERM");
    }
  });
});

describe("createSmartTokenClient — higiene de segredos em memória (RNF-03)", () => {
  it("zera privateKeyPassword após a construção", async () => {
    const { privateKey } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem", cipher: "aes-256-cbc", passphrase: "teste123" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });
    const keyPath = p("encrypted-key.pem");
    await writeFile(keyPath, privateKey as unknown as string);

    const password = Buffer.from("teste123");
    const client = await createSmartTokenClient({
      tokenEndpoint: "https://localhost:9999/token",
      clientId: "c",
      privateKeyPem: keyPath,
      privateKeyPassword: password,
    });
    try {
      expect(password.every((byte) => byte === 0)).toBe(true);
    } finally {
      await client.close();
    }
  });

  it("NÃO zera clientPfx nem clientPfxPassphrase (quebraria reconexões — ver RASTREABILIDADE.md)", async () => {
    const keyPath = p("pfx-key.pem");
    const certPath = p("pfx-cert.pem");
    const p12Path = p("pfx-hygiene.p12");
    execFileSync(
      "openssl",
      ["req", "-x509", "-newkey", "rsa:2048", "-keyout", keyPath, "-out", certPath, "-days", "1", "-nodes", "-subj", "/CN=pfx-teste"],
      { stdio: "ignore" },
    );
    execFileSync(
      "openssl",
      ["pkcs12", "-export", "-inkey", keyPath, "-in", certPath, "-out", p12Path, "-passout", "pass:teste123"],
      { stdio: "ignore" },
    );
    const pfx = await readFile(p12Path);
    const pfxCopyBeforeUse = Buffer.from(pfx);

    const client = await createSmartTokenClient({
      tokenEndpoint: "https://localhost:9999/token",
      clientId: "c",
      signingStrategy: () => new Uint8Array(),
      clientPfx: pfx,
      clientPfxPassphrase: "teste123",
    });
    try {
      expect(pfx.equals(pfxCopyBeforeUse)).toBe(true); // continua intacto, de propósito
    } finally {
      await client.close();
    }
  });
});

describe("createSmartTokenClient — close() é best-effort mesmo com signingStrategy.close() falhando", () => {
  it("client.close() resolve sem lançar quando signingStrategy.close() lança", async () => {
    const signingStrategy = Object.assign(() => new Uint8Array(), {
      close: () => {
        throw new Error("falha simulada ao fechar a estratégia");
      },
    });

    const client = await createSmartTokenClient({
      tokenEndpoint: "https://localhost:9999/token",
      clientId: "c",
      signingStrategy,
    });

    await expect(client.close()).resolves.toBeUndefined();
  });

  it("client.close() resolve sem lançar quando signingStrategy.close() rejeita", async () => {
    const signingStrategy = Object.assign(() => new Uint8Array(), {
      close: () => Promise.reject(new Error("falha simulada ao fechar a estratégia (async)")),
    });

    const client = await createSmartTokenClient({
      tokenEndpoint: "https://localhost:9999/token",
      clientId: "c",
      signingStrategy,
    });

    await expect(client.close()).resolves.toBeUndefined();
  });
});
