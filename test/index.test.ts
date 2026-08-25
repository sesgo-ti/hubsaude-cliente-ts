import { describe, expect, it } from "vitest";
import * as pkg from "../src/index.js";

/**
 * Testa o ponto de entrada público (`src/index.ts`) como um todo — o que
 * de fato fica exposto a quem faz `import { ... } from "hubsaude-cliente-ts"`.
 * Os demais testes exercitam cada módulo individualmente; este garante
 * que o índice reexporta tudo corretamente, sem erro de import, e que a
 * superfície pública não regride silenciosamente.
 */
describe("índice público (src/index.ts)", () => {
  it("reexporta as classes de erro", () => {
    expect(pkg.SmartTokenError).toBeTypeOf("function");
    expect(pkg.SigningError).toBeTypeOf("function");
    expect(new pkg.SmartTokenError("x")).toBeInstanceOf(Error);
    expect(new pkg.SigningError("x")).toBeInstanceOf(Error);
  });

  it("reexporta as funções de PemLoader e as constantes de tamanho mínimo", () => {
    expect(pkg.MIN_RSA_KEY_BITS).toBe(2048);
    expect(pkg.MIN_EC_FIELD_BITS).toBe(256);
    expect(pkg.validateMinimumKeySize).toBeTypeOf("function");
    expect(pkg.loadPrivateKey).toBeTypeOf("function");
    expect(pkg.loadPrivateKeyFromString).toBeTypeOf("function");
    expect(pkg.loadCertificate).toBeTypeOf("function");
    expect(pkg.loadCertificateFromString).toBeTypeOf("function");
  });

  it("reexporta PrivateKeySigningStrategy", () => {
    expect(pkg.createPrivateKeySigningStrategy).toBeTypeOf("function");
    expect(pkg.DEFAULT_DIGEST).toBe("sha384");
  });

  it("reexporta SigningStrategyFactory", () => {
    expect(pkg.fromPrivateKey).toBeTypeOf("function");
    expect(pkg.fromPemFile).toBeTypeOf("function");
    expect(pkg.fromPemString).toBeTypeOf("function");
    expect(pkg.loadPkcs12).toBeTypeOf("function");
    expect(pkg.fromPkcs12).toBeTypeOf("function");
    expect(pkg.jwtAlgorithmToNode).toBeTypeOf("function");
    expect(pkg.fromPrivateKeyForJwt).toBeTypeOf("function");
  });

  it("reexporta SslContextFactory", () => {
    expect(pkg.buildAgent).toBeTypeOf("function");
    expect(pkg.checkCertificateValidity).toBeTypeOf("function");
    expect(pkg.DEFAULT_TLS_PROTOCOL).toBe("TLSv1.3");
  });

  it("reexporta FaultToleranceConfig e seus padrões", () => {
    expect(pkg.resolveFaultToleranceConfig).toBeTypeOf("function");
    expect(pkg.DEFAULT_CONNECT_TIMEOUT_MS).toBe(10_000);
    expect(pkg.DEFAULT_REQUEST_TIMEOUT_MS).toBe(30_000);
    expect(pkg.DEFAULT_ASSERTION_TTL_SECONDS).toBe(60);
    expect(pkg.DEFAULT_MAX_RETRIES).toBe(3);
  });

  it("reexporta o cliente principal e o algoritmo padrão", () => {
    expect(pkg.SmartTokenClient).toBeTypeOf("function");
    expect(pkg.createSmartTokenClient).toBeTypeOf("function");
    expect(pkg.DEFAULT_JWT_ALGORITHM).toBe("RS384");
  });

  it("SmartTokenClient não tem construtor público (só createSmartTokenClient) — reforçado em runtime, não só em tipo", () => {
    // Simula um consumidor JavaScript puro (ou um cast em TS) tentando
    // burlar o `private` do compilador, chamando o construtor direto.
    const Ctor = pkg.SmartTokenClient as unknown as new (...args: unknown[]) => unknown;
    expect(() => new Ctor()).toThrow("SmartTokenClient não tem construtor público");
    expect(() => new Ctor(Symbol("token-forjado"), {}, {})).toThrow(
      "SmartTokenClient não tem construtor público",
    );
  });
});
