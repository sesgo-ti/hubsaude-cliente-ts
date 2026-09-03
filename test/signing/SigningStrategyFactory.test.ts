import { execFileSync } from "node:child_process";
import { constants, createPrivateKey, createPublicKey, generateKeyPairSync, verify } from "node:crypto";
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { SmartTokenError } from "../../src/errors/SmartTokenError.js";
import {
  fromPemFile,
  fromPemString,
  fromPkcs12,
  fromPrivateKey,
  fromPrivateKeyForJwt,
  jwtAlgorithmToNode,
  loadPkcs12,
} from "../../src/signing/SigningStrategyFactory.js";

const DATA = Buffer.from("dados de teste");
const PASSWORD = "teste123";

let dir: string;

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "signing-factory-test-"));
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

function fixturePath(name: string): string {
  return join(dir, name);
}

function generateRsaKeyPem(): string {
  const { privateKey } = generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
  return privateKey as unknown as string;
}

async function generatePkcs12(): Promise<Buffer> {
  const unique = `${Date.now()}-${Math.random()}`;
  const keyPath = fixturePath(`p12-key-${unique}.pem`);
  const certPath = fixturePath(`p12-cert-${unique}.pem`);
  const p12Path = fixturePath(`teste-${unique}.p12`);
  execFileSync(
    "openssl",
    [
      "req",
      "-x509",
      "-newkey",
      "rsa:2048",
      "-keyout",
      keyPath,
      "-out",
      certPath,
      "-days",
      "1",
      "-nodes",
      "-subj",
      "/CN=teste-factory",
    ],
    { stdio: "ignore" },
  );
  execFileSync(
    "openssl",
    ["pkcs12", "-export", "-inkey", keyPath, "-in", certPath, "-out", p12Path, "-passout", `pass:${PASSWORD}`],
    { stdio: "ignore" },
  );
  return readFile(p12Path);
}

describe("fromPrivateKey", () => {
  it("delega para createPrivateKeySigningStrategy", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const strategy = fromPrivateKey(privateKey);

    const signature = await strategy(DATA);

    expect(verify("sha384", DATA, publicKey, signature)).toBe(true);
  });
});

describe("fromPemFile / fromPemString", () => {
  it("carrega e assina a partir de arquivo PEM", async () => {
    const path = fixturePath("factory-key.pem");
    const pem = generateRsaKeyPem();
    await writeFile(path, pem);
    const publicKey = createPublicKey(createPrivateKey(pem));

    const strategy = await fromPemFile(path);
    const signature = await strategy(DATA);

    expect(verify("sha384", DATA, publicKey, signature)).toBe(true);
  });

  it("carrega e assina a partir de string PEM", async () => {
    const pem = generateRsaKeyPem();
    const publicKey = createPublicKey(createPrivateKey(pem));

    const strategy = fromPemString(pem, undefined, "<string>");
    const signature = await strategy(DATA);

    expect(verify("sha384", DATA, publicKey, signature)).toBe(true);
  });
});

describe("loadPkcs12 / fromPkcs12", () => {
  it("extrai chave e certificado de um PKCS#12 válido", async () => {
    const pfx = await generatePkcs12();

    const { privateKey, certificate } = loadPkcs12(pfx, PASSWORD);

    expect(privateKey.asymmetricKeyType).toBe("rsa");
    expect(certificate.subject).toContain("teste-factory");
    expect(certificate.checkPrivateKey(privateKey)).toBe(true);
  });

  it("falha com SmartTokenError para senha incorreta", async () => {
    const pfx = await generatePkcs12();

    expect(() => loadPkcs12(pfx, "senha-errada")).toThrow(SmartTokenError);
  });

  it("falha com SmartTokenError para conteúdo inválido", () => {
    expect(() => loadPkcs12(Buffer.from("não é um PKCS#12"), PASSWORD)).toThrow(SmartTokenError);
  });

  it("assina com a chave extraída do PKCS#12", async () => {
    const pfx = await generatePkcs12();
    const { certificate } = loadPkcs12(pfx, PASSWORD);

    const strategy = fromPkcs12(pfx, PASSWORD);
    const signature = await strategy(DATA);

    expect(verify("sha384", DATA, certificate.publicKey, signature)).toBe(true);
  });
});

describe("jwtAlgorithmToNode", () => {
  it.each([
    ["RS256", { digest: "sha256" }],
    ["RS384", { digest: "sha384" }],
    ["RS512", { digest: "sha512" }],
    ["ES256", { digest: "sha256", dsaEncoding: "ieee-p1363" }],
    ["ES384", { digest: "sha384", dsaEncoding: "ieee-p1363" }],
    ["ES512", { digest: "sha512", dsaEncoding: "ieee-p1363" }],
  ] as const)("mapeia %s corretamente", (jwa, expected) => {
    expect(jwtAlgorithmToNode(jwa)).toEqual(expected);
  });

  it("mapeia os algoritmos PS* com padding e saltLength", () => {
    expect(jwtAlgorithmToNode("PS256")).toEqual({
      digest: "sha256",
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    });
    expect(jwtAlgorithmToNode("PS384")).toEqual({
      digest: "sha384",
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 48,
    });
    expect(jwtAlgorithmToNode("PS512")).toEqual({
      digest: "sha512",
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 64,
    });
  });

  it("é case-insensitive", () => {
    expect(jwtAlgorithmToNode("rs384")).toEqual({ digest: "sha384" });
  });

  it("lança SmartTokenError para algoritmo não reconhecido", () => {
    expect(() => jwtAlgorithmToNode("HS256")).toThrow(SmartTokenError);
  });

  it('rejeita explicitamente o algoritmo "none" (vulnerabilidade clássica de JWT)', () => {
    expect(() => jwtAlgorithmToNode("none")).toThrow(SmartTokenError);
  });
});

describe("fromPrivateKeyForJwt", () => {
  it("assina RS384 corretamente", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

    const strategy = fromPrivateKeyForJwt(privateKey, "RS384");
    const signature = await strategy(DATA);

    expect(verify("sha384", DATA, publicKey, signature)).toBe(true);
  });

  it("assina ES256 no formato bruto R||S", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });

    const strategy = fromPrivateKeyForJwt(privateKey, "ES256");
    const signature = await strategy(DATA);

    expect(signature.length).toBe(64);
    expect(verify("sha256", DATA, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature)).toBe(true);
  });

  it("assina PS256 corretamente (RSA-PSS)", async () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

    const strategy = fromPrivateKeyForJwt(privateKey, "PS256");
    const signature = await strategy(DATA);

    expect(
      verify("sha256", DATA, { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 }, signature),
    ).toBe(true);
  });
});
