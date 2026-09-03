import { generateKeyPairSync } from "node:crypto";
import { writeFileSync } from "node:fs";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import forge from "node-forge";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SmartTokenError } from "../../src/errors/SmartTokenError.js";
import {
  clearPassword,
  loadCertificate,
  loadCertificateFromString,
  loadPrivateKey,
  loadPrivateKeyFromString,
  MIN_RSA_KEY_BITS,
  validateMinimumKeySize,
} from "../../src/signing/PemLoader.js";

const PASSWORD = "teste123";

let dir: string;

function fixturePath(name: string): string {
  return join(dir, name);
}

/** Gera um par de chaves RSA e devolve o PEM da privada no formato pedido. */
function generateRsaPem(
  type: "pkcs1" | "pkcs8",
  options: { cipher?: string; passphrase?: string; modulusLength?: number } = {},
): string {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: options.modulusLength ?? 2048,
    privateKeyEncoding: {
      type,
      format: "pem",
      ...(options.cipher ? { cipher: options.cipher, passphrase: options.passphrase } : {}),
    },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return privateKey as unknown as string;
}

/**
 * Gera um certificado autoassinado com validade customizável, via
 * `node-forge` (já dependência do projeto) em vez da CLI do OpenSSL —
 * `notBefore`/`notAfter` como objetos `Date` nativos, sem depender de
 * uma versão específica do OpenSSL instalada no ambiente.
 */
function generateSelfSignedCert(notBefore: Date, notAfter: Date): string {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();
  cert.publicKey = keys.publicKey;
  cert.serialNumber = "01";
  cert.validity.notBefore = notBefore;
  cert.validity.notAfter = notAfter;
  const attrs = [{ name: "commonName", value: "teste-pemloader" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);
  cert.sign(keys.privateKey, forge.md.sha256.create());

  const certPath = fixturePath(`cert-${notBefore.getTime()}.pem`);
  writeFileSync(certPath, forge.pki.certificateToPem(cert));
  return certPath;
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "pemloader-test-"));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("loadPrivateKey / loadPrivateKeyFromString", () => {
  it("carrega chave PKCS#8 não criptografada de arquivo", async () => {
    const path = fixturePath("pkcs8-plain.pem");
    await writeFile(path, generateRsaPem("pkcs8"));

    const key = await loadPrivateKey(path);

    expect(key.asymmetricKeyType).toBe("rsa");
  });

  it("carrega chave PKCS#1 não criptografada", async () => {
    const path = fixturePath("pkcs1-plain.pem");
    await writeFile(path, generateRsaPem("pkcs1"));

    const key = await loadPrivateKey(path);

    expect(key.asymmetricKeyType).toBe("rsa");
  });

  it("carrega chave PKCS#8 criptografada com a senha correta", async () => {
    const path = fixturePath("pkcs8-encrypted.pem");
    await writeFile(path, generateRsaPem("pkcs8", { cipher: "aes-256-cbc", passphrase: PASSWORD }));

    const key = await loadPrivateKey(path, Buffer.from(PASSWORD));

    expect(key.asymmetricKeyType).toBe("rsa");
  });

  it("carrega chave no formato tradicional OpenSSL (PKCS#1 + DEK-Info) com senha correta", async () => {
    const path = fixturePath("pkcs1-deskinfo.pem");
    const pem = generateRsaPem("pkcs1", { cipher: "aes-256-cbc", passphrase: PASSWORD });
    await writeFile(path, pem);
    expect(pem).toContain("DEK-Info");

    const key = await loadPrivateKey(path, Buffer.from(PASSWORD));

    expect(key.asymmetricKeyType).toBe("rsa");
  });

  it("falha com SmartTokenError quando a chave criptografada não recebe senha", async () => {
    const path = fixturePath("pkcs8-encrypted-sem-senha.pem");
    await writeFile(path, generateRsaPem("pkcs8", { cipher: "aes-256-cbc", passphrase: PASSWORD }));

    await expect(loadPrivateKey(path)).rejects.toThrow(SmartTokenError);
  });

  it("falha com SmartTokenError quando a senha está incorreta", async () => {
    const path = fixturePath("pkcs8-encrypted-senha-errada.pem");
    await writeFile(path, generateRsaPem("pkcs8", { cipher: "aes-256-cbc", passphrase: PASSWORD }));

    await expect(loadPrivateKey(path, Buffer.from("senha-errada"))).rejects.toThrow(SmartTokenError);
  });

  it("falha com SmartTokenError para arquivo PEM vazio", async () => {
    const path = fixturePath("vazio.pem");
    await writeFile(path, "");

    await expect(loadPrivateKey(path)).rejects.toThrow(SmartTokenError);
  });

  it("falha com SmartTokenError quando o conteúdo não é uma chave privada", () => {
    expect(() => loadPrivateKeyFromString("não é um PEM válido", undefined, "<string>")).toThrow(SmartTokenError);
  });

  it("falha com RangeError para chave RSA abaixo do tamanho mínimo", () => {
    const weakPem = generateRsaPem("pkcs8", { modulusLength: 512 });

    expect(() => loadPrivateKeyFromString(weakPem, undefined, "<string>")).toThrow(RangeError);
  });

  it("carrega chave a partir de string", () => {
    const pem = generateRsaPem("pkcs8");

    const key = loadPrivateKeyFromString(pem, undefined, "<string>");

    expect(key.asymmetricKeyType).toBe("rsa");
  });

  it("zera a senha mesmo quando a chave carregada não é criptografada (senha desnecessária)", async () => {
    const path = fixturePath("pkcs8-plain-com-senha-desnecessaria.pem");
    await writeFile(path, generateRsaPem("pkcs8"));
    const password = Buffer.from("senha-que-nao-era-necessaria");

    const key = await loadPrivateKey(path, password);

    expect(key.asymmetricKeyType).toBe("rsa");
    expect(password.every((byte) => byte === 0)).toBe(true);
  });
});

describe("validateMinimumKeySize", () => {
  it("aceita chave RSA no tamanho mínimo exato", () => {
    const pem = generateRsaPem("pkcs8", { modulusLength: MIN_RSA_KEY_BITS });
    const key = loadPrivateKeyFromString(pem, undefined, "<string>");

    expect(() => validateMinimumKeySize(key, "<teste>")).not.toThrow();
  });
});

describe("clearPassword", () => {
  it("zera o buffer da senha", () => {
    const password = Buffer.from("segredo");

    clearPassword(password);

    expect(password.every((byte) => byte === 0)).toBe(true);
  });

  it("aceita undefined sem falhar", () => {
    expect(() => clearPassword(undefined)).not.toThrow();
  });
});

describe("loadCertificate / loadCertificateFromString", () => {
  it("carrega certificado válido de arquivo", async () => {
    const certPath = generateSelfSignedCert(new Date("2024-01-01T00:00:00Z"), new Date("2099-01-01T00:00:00Z"));

    const cert = await loadCertificate(certPath);

    expect(cert.subject).toContain("teste-pemloader");
  });

  it("carrega certificado válido de string", async () => {
    const certPath = generateSelfSignedCert(new Date("2024-01-01T00:00:00Z"), new Date("2099-01-01T00:00:00Z"));
    const pem = await import("node:fs/promises").then((fs) => fs.readFile(certPath, "utf8"));

    const cert = loadCertificateFromString(pem, "<string>");

    expect(cert.subject).toContain("teste-pemloader");
  });

  it("falha com SmartTokenError para certificado expirado", async () => {
    const certPath = generateSelfSignedCert(new Date("2020-01-01T00:00:00Z"), new Date("2020-06-01T00:00:00Z"));

    await expect(loadCertificate(certPath)).rejects.toThrow(SmartTokenError);
  });

  it("falha com SmartTokenError para certificado ainda não válido", async () => {
    const certPath = generateSelfSignedCert(new Date("2099-01-01T00:00:00Z"), new Date("2100-01-01T00:00:00Z"));

    await expect(loadCertificate(certPath)).rejects.toThrow(SmartTokenError);
  });

  it("falha com SmartTokenError quando o arquivo não contém um certificado", async () => {
    const path = fixturePath("nao-e-certificado.pem");
    await writeFile(path, generateRsaPem("pkcs8"));

    await expect(loadCertificate(path)).rejects.toThrow(SmartTokenError);
  });
});
