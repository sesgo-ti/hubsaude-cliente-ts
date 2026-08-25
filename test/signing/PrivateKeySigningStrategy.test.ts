import { constants, generateKeyPairSync, verify } from "node:crypto";
import { describe, expect, it } from "vitest";
import { SigningError } from "../../src/errors/SigningError.js";
import { createPrivateKeySigningStrategy } from "../../src/signing/PrivateKeySigningStrategy.js";

const DATA = Buffer.from("dados de teste");

function generateRsaPair(modulusLength = 2048) {
  return generateKeyPairSync("rsa", { modulusLength });
}

function generateEcPair() {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

describe("createPrivateKeySigningStrategy", () => {
  it("assina com o digest padrão (sha384) e produz assinatura verificável", async () => {
    const { privateKey, publicKey } = generateRsaPair();
    const strategy = createPrivateKeySigningStrategy(privateKey);

    const signature = await strategy(DATA);

    expect(verify("sha384", DATA, publicKey, signature)).toBe(true);
  });

  it("assina com digest customizado", async () => {
    const { privateKey, publicKey } = generateRsaPair();
    const strategy = createPrivateKeySigningStrategy(privateKey, { digest: "sha256" });

    const signature = await strategy(DATA);

    expect(verify("sha256", DATA, publicKey, signature)).toBe(true);
  });

  it("assina com RSA-PSS (padding + saltLength)", async () => {
    const { privateKey, publicKey } = generateRsaPair();
    const strategy = createPrivateKeySigningStrategy(privateKey, {
      digest: "sha256",
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    });

    const signature = await strategy(DATA);

    expect(
      verify(
        "sha256",
        DATA,
        { key: publicKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 32 },
        signature,
      ),
    ).toBe(true);
  });

  it("assina EC no formato bruto R||S (ieee-p1363), exigido pelo JWS", async () => {
    const { privateKey, publicKey } = generateEcPair();
    const strategy = createPrivateKeySigningStrategy(privateKey, {
      digest: "sha256",
      dsaEncoding: "ieee-p1363",
    });

    const signature = await strategy(DATA);

    expect(signature.length).toBe(64); // P-256: 32 bytes de R + 32 bytes de S
    expect(
      verify("sha256", DATA, { key: publicKey, dsaEncoding: "ieee-p1363" }, signature),
    ).toBe(true);
  });

  it("rejeita chave RSA abaixo do tamanho mínimo", () => {
    const { privateKey } = generateRsaPair(512);

    expect(() => createPrivateKeySigningStrategy(privateKey)).toThrow(RangeError);
  });

  it("lança SigningError quando a operação de assinatura falha", () => {
    const { publicKey } = generateRsaPair();
    // Um KeyObject de chave pública não serve para assinar — crypto.sign falhará.
    // Esta implementação é síncrona, então o erro é lançado na hora (não
    // como Promise rejeitada) — mas quem consome uma SigningStrategy
    // genérica deve sempre envolver `await strategy(data)` em try/catch,
    // pois outras implementações podem rejeitar de forma assíncrona.
    const strategy = createPrivateKeySigningStrategy(publicKey);

    expect(() => strategy(DATA)).toThrow(SigningError);
  });
});
