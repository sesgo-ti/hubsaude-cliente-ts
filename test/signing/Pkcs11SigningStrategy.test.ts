/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import { execFileSync } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import pkcs11js, { type Attribute } from "pkcs11js";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createSmartTokenClient } from "../../src/client/SmartTokenClient.js";
import { SigningError } from "../../src/errors/SigningError.js";
import { SmartTokenError } from "../../src/errors/SmartTokenError.js";
import { fromPkcs11 } from "../../src/signing/Pkcs11SigningStrategy.js";

/**
 * Estes testes exigem o SoftHSM2 instalado no ambiente (`softhsm2-util`
 * e o módulo `libsofthsm2.so`) — um HSM em software, real o bastante
 * para exercitar o protocolo PKCS#11 de ponta a ponta (sem mock). É um
 * requisito de ambiente de desenvolvimento adicional desta lib, análogo
 * ao `openssl` já exigido pelos testes de TLS/mTLS.
 *
 * O caminho do módulo varia por distribuição (`/usr/lib/softhsm/...`,
 * `/usr/lib/x86_64-linux-gnu/softhsm/...`, `/usr/lib64/pkcs11/...`,
 * etc.) — defina `SOFTHSM_LIB` para o caminho correto no seu ambiente
 * se o padrão não funcionar.
 */
const SOFTHSM_LIB = process.env.SOFTHSM_LIB ?? "/usr/lib/softhsm/libsofthsm2.so";
const SO_PIN = "0000";
const PIN = "123456";

let dir: string;
let confPath: string;

function softhsm2Util(args: string[]): void {
  execFileSync("softhsm2-util", args, { env: { ...process.env, SOFTHSM2_CONF: confPath }, stdio: "ignore" });
}

/** Inicializa um token novo e isolado, com o label dado. */
function initToken(label: string): void {
  softhsm2Util(["--init-token", "--free", "--label", label, "--so-pin", SO_PIN, "--pin", PIN]);
}

/** Gera um par de chaves RSA-2048 dentro do token, via pkcs11js puro (não a lib). */
function generateRsaKeyPair(tokenLabel: string, keyLabel: string, keyId?: Buffer): void {
  withRawSession(tokenLabel, (p11, session) => {
    const pub: Attribute[] = [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_TOKEN, value: true },
      { type: pkcs11js.CKA_MODULUS_BITS, value: 2048 },
      { type: pkcs11js.CKA_PUBLIC_EXPONENT, value: Buffer.from([0x01, 0x00, 0x01]) },
      { type: pkcs11js.CKA_VERIFY, value: true },
      { type: pkcs11js.CKA_LABEL, value: keyLabel },
    ];
    const priv: Attribute[] = [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_TOKEN, value: true },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_SIGN, value: true },
      { type: pkcs11js.CKA_LABEL, value: keyLabel },
    ];
    if (keyId !== undefined) {
      pub.push({ type: pkcs11js.CKA_ID, value: keyId });
      priv.push({ type: pkcs11js.CKA_ID, value: keyId });
    }
    p11.C_GenerateKeyPair(session, { mechanism: pkcs11js.CKM_RSA_PKCS_KEY_PAIR_GEN }, pub, priv);
  });
}

/** OID DER da curva secp384r1 (P-384), formato exigido por CKA_EC_PARAMS. */
const P384_OID = Buffer.from("06052b81040022", "hex");

/** Gera um par de chaves EC P-384 dentro do token, via pkcs11js puro (não a lib). */
function generateEcKeyPair(tokenLabel: string, keyLabel: string): void {
  withRawSession(tokenLabel, (p11, session) => {
    const pub = [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_TOKEN, value: true },
      { type: pkcs11js.CKA_EC_PARAMS, value: P384_OID },
      { type: pkcs11js.CKA_VERIFY, value: true },
      { type: pkcs11js.CKA_LABEL, value: keyLabel },
    ];
    const priv = [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PRIVATE_KEY },
      { type: pkcs11js.CKA_TOKEN, value: true },
      { type: pkcs11js.CKA_PRIVATE, value: true },
      { type: pkcs11js.CKA_SIGN, value: true },
      { type: pkcs11js.CKA_LABEL, value: keyLabel },
    ];
    p11.C_GenerateKeyPair(session, { mechanism: pkcs11js.CKM_ECDSA_KEY_PAIR_GEN }, pub, priv);
  });
}

/**
 * Chama C_Initialize/C_Login tolerando "já inicializado"/"já logado" —
 * o módulo nativo é um singleton por processo e o login é por token,
 * não por sessão (confirmado empiricamente contra SoftHSM2; ver a
 * mesma tolerância em Pkcs11SigningStrategy.ts).
 */
function tolerateAlready<T>(fn: () => T, code: number): T | undefined {
  try {
    return fn();
  } catch (err) {
    if ((err as { code?: number }).code === code) {
      return undefined;
    }
    throw err;
  }
}

/** Abre uma sessão autenticada e crua (sem passar pela lib) para preparar o token de teste. */
function withRawSession(tokenLabel: string, fn: (p11: pkcs11js.PKCS11, session: Buffer) => void): void {
  process.env.SOFTHSM2_CONF = confPath;
  const p11 = new pkcs11js.PKCS11();
  p11.load(SOFTHSM_LIB);
  tolerateAlready(() => p11.C_Initialize(), pkcs11js.CKR_CRYPTOKI_ALREADY_INITIALIZED);
  try {
    const slots = p11.C_GetSlotList(true);
    const slot = slots.find((s) => p11.C_GetTokenInfo(s).label.trim() === tokenLabel);
    if (slot === undefined) {
      throw new Error(`Token de teste '${tokenLabel}' não encontrado`);
    }
    const session = p11.C_OpenSession(slot, pkcs11js.CKF_SERIAL_SESSION | pkcs11js.CKF_RW_SESSION);
    tolerateAlready(() => p11.C_Login(session, pkcs11js.CKU_USER, PIN), pkcs11js.CKR_USER_ALREADY_LOGGED_IN);
    try {
      fn(p11, session);
    } finally {
      tolerateAlready(() => p11.C_Logout(session), pkcs11js.CKR_USER_NOT_LOGGED_IN);
      p11.C_CloseSession(session);
    }
  } finally {
    p11.C_Finalize();
  }
}

/** Verifica uma assinatura crua contra o token — usado só para validar os testes, não a lib. */
function verifyRaw(tokenLabel: string, keyLabel: string, mechanism: number, data: Buffer, signature: Uint8Array): boolean {
  let valid = false;
  withRawSession(tokenLabel, (p11, session) => {
    p11.C_FindObjectsInit(session, [
      { type: pkcs11js.CKA_CLASS, value: pkcs11js.CKO_PUBLIC_KEY },
      { type: pkcs11js.CKA_LABEL, value: keyLabel },
    ]);
    const pub = p11.C_FindObjects(session);
    p11.C_FindObjectsFinal(session);
    if (pub === null) {
      throw new Error(`Chave pública '${keyLabel}' não encontrada`);
    }
    p11.C_VerifyInit(session, { mechanism }, pub);
    valid = p11.C_Verify(session, data, Buffer.from(signature));
  });
  return valid;
}

beforeAll(async () => {
  dir = await mkdtemp(join(tmpdir(), "pkcs11-test-"));
  confPath = join(dir, "softhsm2.conf");
  await writeFile(confPath, `directories.tokendir = ${join(dir, "tokens")}\nobjectstore.backend = file\nlog.level = ERROR\n`);
  await import("node:fs/promises").then((fs) => fs.mkdir(join(dir, "tokens")));

  initToken("token-rs384");
  generateRsaKeyPair("token-rs384", "chave-rs384");
  generateRsaKeyPair("token-rs384", "chave-com-id", Buffer.from("id-01", "utf8"));
  initToken("token-es384");
  generateEcKeyPair("token-es384", "chave-es384");
  // Token dedicado, nunca autenticado por nenhum outro teste: o login é
  // por token (não por sessão) no SoftHSM2, então testar PIN incorreto
  // num token já logado por outro teste mascararia o erro real
  // (CKR_USER_ALREADY_LOGGED_IN em vez de credencial inválida).
  initToken("token-badpin");
});

afterAll(async () => {
  await rm(dir, { recursive: true, force: true });
});

describe("fromPkcs11", () => {
  it("assina com RS384 (padrão) e a assinatura é válida contra o próprio token", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    const strategy = await fromPkcs11({
      library: SOFTHSM_LIB,
      pin: PIN,
      tokenLabel: "token-rs384",
      keyLabel: "chave-rs384",
    });

    const data = Buffer.from("dados de teste RS384", "utf8");
    const signature = await strategy(data);

    expect(verifyRaw("token-rs384", "chave-rs384", pkcs11js.CKM_SHA384_RSA_PKCS, data, signature)).toBe(true);
  });

  it("assina com ES384 e devolve o formato bruto R||S (96 bytes para P-384)", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    const strategy = await fromPkcs11({
      library: SOFTHSM_LIB,
      pin: PIN,
      tokenLabel: "token-es384",
      keyLabel: "chave-es384",
      jwtAlgorithm: "ES384",
    });

    const data = Buffer.from("dados de teste ES384", "utf8");
    const signature = await strategy(data);

    expect(signature.length).toBe(96);
    expect(verifyRaw("token-es384", "chave-es384", pkcs11js.CKM_ECDSA_SHA384, data, signature)).toBe(true);
  });

  it("reutiliza a mesma sessão em assinaturas sucessivas (sem reautenticar)", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    const strategy = await fromPkcs11({
      library: SOFTHSM_LIB,
      pin: PIN,
      tokenLabel: "token-rs384",
      keyLabel: "chave-rs384",
    });

    const sig1 = await strategy(Buffer.from("primeira", "utf8"));
    const sig2 = await strategy(Buffer.from("segunda", "utf8"));

    expect(sig1).not.toEqual(sig2);
    expect(
      verifyRaw("token-rs384", "chave-rs384", pkcs11js.CKM_SHA384_RSA_PKCS, Buffer.from("segunda", "utf8"), sig2),
    ).toBe(true);
  });

  it("rejeita com SmartTokenError quando o PIN está incorreto", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    await expect(
      fromPkcs11({ library: SOFTHSM_LIB, pin: "pin-errado", tokenLabel: "token-badpin", keyLabel: "chave-rs384" }),
    ).rejects.toThrow(SmartTokenError);
  });

  it("rejeita com SmartTokenError quando a chave não existe", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    await expect(
      fromPkcs11({ library: SOFTHSM_LIB, pin: PIN, tokenLabel: "token-rs384", keyLabel: "nao-existe" }),
    ).rejects.toThrow(SmartTokenError);
  });

  it("rejeita com SmartTokenError quando o token com o label informado não existe", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    await expect(
      fromPkcs11({ library: SOFTHSM_LIB, pin: PIN, tokenLabel: "nao-existe", keyLabel: "chave-rs384" }),
    ).rejects.toThrow(SmartTokenError);
  });

  it("rejeita com SmartTokenError quando o módulo PKCS#11 não existe", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    await expect(
      fromPkcs11({ library: "/caminho/inexistente.so", pin: PIN, tokenLabel: "token-rs384", keyLabel: "chave-rs384" }),
    ).rejects.toThrow(SmartTokenError);
  });

  it("lança Error quando slot e tokenLabel são fornecidos juntos", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    await expect(
      fromPkcs11({ library: SOFTHSM_LIB, pin: PIN, slot: 0, tokenLabel: "token-rs384", keyLabel: "chave-rs384" }),
    ).rejects.toThrow("Defina slot OU tokenLabel");
  });

  it("rejeita com SmartTokenError para algoritmo JWT não suportado", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    await expect(
      fromPkcs11({
        library: SOFTHSM_LIB,
        pin: PIN,
        tokenLabel: "token-rs384",
        keyLabel: "chave-rs384",
        jwtAlgorithm: "HS256",
      }),
    ).rejects.toThrow(SmartTokenError);
  });

  it("lança SigningError quando o mecanismo é incompatível com o tipo da chave", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    // chave-rs384 é uma chave RSA; pedir ES384 seleciona CKM_ECDSA_SHA384,
    // um mecanismo só-EC — falha real de assinatura no token, não um erro
    // de configuração detectável antes de tentar assinar (handles PKCS#11
    // são opacos; não validamos o tipo da chave antecipadamente, mesma
    // postura documentada para chaves PKCS#11 na especificação).
    const strategy = await fromPkcs11({
      library: SOFTHSM_LIB,
      pin: PIN,
      tokenLabel: "token-rs384",
      keyLabel: "chave-rs384",
      jwtAlgorithm: "ES384",
    });

    await expect(strategy(Buffer.from("dados", "utf8"))).rejects.toThrow(SigningError);
  });

  it("localiza a chave por keyId, sem keyLabel", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    const strategy = await fromPkcs11({
      library: SOFTHSM_LIB,
      pin: PIN,
      tokenLabel: "token-rs384",
      keyId: Buffer.from("id-01", "utf8"),
    });

    const data = Buffer.from("localizado por id", "utf8");
    const signature = await strategy(data);

    expect(verifyRaw("token-rs384", "chave-com-id", pkcs11js.CKM_SHA384_RSA_PKCS, data, signature)).toBe(true);
  });

  it("localiza a chave combinando keyLabel e keyId", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    const strategy = await fromPkcs11({
      library: SOFTHSM_LIB,
      pin: PIN,
      tokenLabel: "token-rs384",
      keyLabel: "chave-com-id",
      keyId: Buffer.from("id-01", "utf8"),
    });

    const data = Buffer.from("localizado por label e id", "utf8");
    const signature = await strategy(data);

    expect(verifyRaw("token-rs384", "chave-com-id", pkcs11js.CKM_SHA384_RSA_PKCS, data, signature)).toBe(true);
  });

  it("lança Error quando nem keyLabel nem keyId são informados", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    await expect(
      fromPkcs11({ library: SOFTHSM_LIB, pin: PIN, tokenLabel: "token-rs384" }),
    ).rejects.toThrow("Defina keyLabel e/ou keyId");
  });

  it("close() encerra a sessão — assinar depois de fechar falha", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    const strategy = await fromPkcs11({
      library: SOFTHSM_LIB,
      pin: PIN,
      tokenLabel: "token-rs384",
      keyLabel: "chave-rs384",
    });

    // Confirma que funciona antes de fechar.
    await strategy(Buffer.from("antes de fechar", "utf8"));

    await strategy.close?.();

    await expect(strategy(Buffer.from("depois de fechar", "utf8"))).rejects.toThrow(SigningError);
  });

  it("createSmartTokenClient.close() fecha a sessão PKCS#11 subjacente", async () => {
    process.env.SOFTHSM2_CONF = confPath;
    const strategy = await fromPkcs11({
      library: SOFTHSM_LIB,
      pin: PIN,
      tokenLabel: "token-rs384",
      keyLabel: "chave-rs384",
    });

    const client = await createSmartTokenClient({
      tokenEndpoint: "https://exemplo.invalido/token",
      clientId: "c",
      signingStrategy: strategy,
    });

    await client.close();

    // A sessão PKCS#11 foi fechada como parte do close() do cliente —
    // chamar a estratégia diretamente (fora do cliente já fechado) prova
    // que o encerramento foi propagado, não só que o cliente rejeita uso.
    await expect(strategy(Buffer.from("depois do close do cliente", "utf8"))).rejects.toThrow(SigningError);
  });
});
