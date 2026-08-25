import { execFileSync } from "node:child_process";
import { createPrivateKey, generateKeyPairSync, X509Certificate } from "node:crypto";
import { mkdtemp, rm, writeFile, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SmartTokenError } from "../../src/errors/SmartTokenError.js";
import { verifyKeyPair } from "../../src/signing/KeyCertificateConsistency.js";

let dir: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "keycert-test-"));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

/** Gera um par chave+certificado autoassinado (mesmo par) para o algoritmo pedido. */
async function generateMatchingPair(algorithm: "rsa" | "ec"): Promise<{ key: string; cert: X509Certificate }> {
  const { privateKey } =
    algorithm === "rsa"
      ? generateKeyPairSync("rsa", {
          modulusLength: 2048,
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
          publicKeyEncoding: { type: "spki", format: "pem" },
        })
      : generateKeyPairSync("ec", {
          namedCurve: "prime256v1",
          privateKeyEncoding: { type: "pkcs8", format: "pem" },
          publicKeyEncoding: { type: "spki", format: "pem" },
        });

  const keyPath = join(dir, `${algorithm}-${Date.now()}-key.pem`);
  const certPath = join(dir, `${algorithm}-${Date.now()}-cert.pem`);
  await writeFile(keyPath, privateKey as unknown as string);
  execFileSync(
    "openssl",
    ["req", "-x509", "-new", "-key", keyPath, "-out", certPath, "-days", "1", "-subj", "/CN=teste"],
    { stdio: "ignore" },
  );

  return { key: privateKey as unknown as string, cert: new X509Certificate(await readFile(certPath)) };
}

describe("verifyKeyPair", () => {
  it("não lança para par RSA válido", async () => {
    const { key, cert } = await generateMatchingPair("rsa");

    expect(() => verifyKeyPair(createPrivateKey(key), cert)).not.toThrow();
  });

  it("não lança para par EC válido", async () => {
    const { key, cert } = await generateMatchingPair("ec");

    expect(() => verifyKeyPair(createPrivateKey(key), cert)).not.toThrow();
  });

  it("lança SmartTokenError quando a chave não corresponde ao certificado", async () => {
    const { cert } = await generateMatchingPair("rsa");
    const { privateKey: outraChave } = generateKeyPairSync("rsa", {
      modulusLength: 2048,
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    expect(() => verifyKeyPair(createPrivateKey(outraChave), cert)).toThrow(SmartTokenError);
  });

  it("lança SmartTokenError para tipo de chave não suportado (ed25519)", async () => {
    const { cert } = await generateMatchingPair("rsa");
    const { privateKey: chaveEd25519 } = generateKeyPairSync("ed25519", {
      privateKeyEncoding: { type: "pkcs8", format: "pem" },
      publicKeyEncoding: { type: "spki", format: "pem" },
    });

    expect(() => verifyKeyPair(createPrivateKey(chaveEd25519), cert)).toThrow(SmartTokenError);
  });
});
