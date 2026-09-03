/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import { randomUUID, type KeyObject } from "node:crypto";
import * as http from "node:http";
import type { IncomingMessage } from "node:http";
import * as https from "node:https";
import { SmartTokenError } from "../errors/SmartTokenError.js";
import { NOOP_LOGGER, type Logger } from "../logging/Logger.js";
import {
  httpFailure,
  isConfirmedClientCertificateRejection,
  isLikelyClientCertificateRejection,
  isTransientNetworkFailure,
} from "../resilience/ErrorClassifier.js";
import {
  resolveFaultToleranceConfig,
  type FaultToleranceConfig,
  type FaultToleranceOptions,
} from "../resilience/FaultToleranceConfig.js";
import { computeRetryDelayMs } from "../resilience/RetryPolicy.js";
import { loadCertificate, loadPrivateKey } from "../signing/PemLoader.js";
import { fromPrivateKeyForJwt, jwtAlgorithmToNode } from "../signing/SigningStrategyFactory.js";
import type { CloseableSigningStrategy, SigningStrategy } from "../signing/SigningStrategy.js";
import { verifyKeyPair } from "../signing/KeyCertificateConsistency.js";
import { discoverTokenEndpoint, requireHttps } from "../token/SmartConfigurationDiscovery.js";
import { readBoundedText, sanitizeExpiresIn } from "../token/TokenResponseGuard.js";
import { TokenCacheStrategy, type RawTokenResponse, type TokenResponse } from "../token/TokenCacheStrategy.js";
import { buildAgent, checkCertificateValidity, type TlsMaterial } from "../tls/SslContextFactory.js";
import { generateTraceContext, traceparent, TRACEPARENT_HEADER, type TraceContext } from "../trace/TraceContext.js";

export type { TokenResponse } from "../token/TokenCacheStrategy.js";

/** Algoritmo JWT padrão (RS384 — o HubSaúde aceita apenas RS384 e ES384). */
export const DEFAULT_JWT_ALGORITHM = "RS384";

const GRANT_TYPE = "client_credentials";
const ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const HTTP_OK = 200;

const HUB_CTX_IG_PATTERN = /^[a-z][a-z0-9-]{1,30}$/;
const HUB_CTX_VERSAO_PATTERN = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/;

/** Contexto de Guia de Implementação (claim `hub_ctx`) do `client_assertion`. */
export interface HubContext {
  /** Alias do Guia de Implementação — `[a-z][a-z0-9-]{1,30}` (ex.: `"hemograma"`). */
  ig: string;
  /** Versão SemVer completa `MAJOR.MINOR.PATCH`, sem pre-release (ex.: `"0.0.1"`). */
  versao: string;
}

/**
 * Opções de construção do {@link SmartTokenClient} (ver
 * {@link createSmartTokenClient}).
 *
 * Substitui o builder fluente do Java por um único objeto de opções —
 * idiomático em TypeScript (ESPECIFICACAO.md §9.1) e necessário de
 * qualquer forma, já que construtores JS/TS não podem ser assíncronos e
 * a construção envolve I/O (ler PEM, opcionalmente descobrir o endpoint
 * via rede).
 */
export interface SmartTokenClientOptions {
  /** URL completa do token endpoint. Mutuamente exclusivo com `fhirBase`. */
  tokenEndpoint?: string;
  /** URL base FHIR para descoberta via `.well-known/smart-configuration`. Mutuamente exclusivo com `tokenEndpoint`. */
  fhirBase?: string;
  /** Identificador do cliente, emitido no credenciamento (Ganesha). */
  clientId: string;

  /** Caminho do arquivo PEM da chave privada. Mutuamente exclusivo com `signingStrategy`. */
  privateKeyPem?: string;
  /** Senha da chave privada PEM criptografada; zerada após o uso. */
  privateKeyPassword?: Buffer;
  /** Estratégia de assinatura pronta (HSM, cofre etc.). Mutuamente exclusivo com `privateKeyPem`. */
  signingStrategy?: SigningStrategy;

  /** Caminho do certificado do cliente (PEM), para mTLS via chave em memória. */
  certificatePem?: string;
  /**
   * Alternativa a `certificatePem`: contêiner PKCS#12/PFX completo
   * (chave + certificado) para mTLS.
   *
   * **Não é zerado pela lib, propositalmente**: diferente de
   * `privateKeyPassword` (consumido uma única vez, na hora, para extrair
   * a chave), o `https.Agent` mantém este buffer e faz o parsing do
   * PKCS#12 de novo a cada nova conexão TCP subjacente — inclusive
   * reconexões, ao longo de toda a vida do cliente (confirmado
   * empiricamente contra `https.Agent`, não só contra o `undici` usado
   * antes: o comportamento é o mesmo nos dois). Zerá-lo depois de
   * `createSmartTokenClient` quebraria conexões futuras (confirmado
   * empiricamente). Se a higiene desse buffer específico for uma
   * preocupação, avalie isso no seu próprio código antes de passá-lo
   * pra cá.
   */
  clientPfx?: Buffer;
  /**
   * Senha do `clientPfx`.
   *
   * Precisa ser `string`, não `Buffer` — diferente das demais senhas
   * desta lib: `tls.ConnectionOptions.passphrase`/`https.AgentOptions.passphrase`
   * (a API do Node usada por baixo) só aceita `string`, então não há
   * como receber isso como um buffer zerável. Como qualquer `string` em
   * JS/TS, não pode ser apagada da memória por código nenhum, nem o
   * nosso — permanece até a coleta de lixo.
   */
  clientPfxPassphrase?: string;
  /** Caminho de um certificado de CA customizado para validar o servidor; omitido usa o trust store padrão do Node. */
  serverTrustAnchor?: string;
  /** Protocolo TLS mínimo (padrão `"TLSv1.3"`). */
  tlsProtocol?: TlsMaterial["tlsProtocol"];

  /** Algoritmo JWT do `client_assertion` (padrão `"RS384"`). */
  jwtAlgorithm?: string;
  /** Identificador da chave (`kid`) no header do JWT, quando o servidor publica múltiplas chaves. */
  keyId?: string;
  /** Contexto de Guia de Implementação (claim `hub_ctx`), quando aplicável. */
  hubContext?: HubContext;

  /** Timeout de conexão TCP, em milissegundos (padrão 10s). */
  connectTimeoutMs?: number;
  /** Timeout de requisição HTTP completa, em milissegundos (padrão 30s). */
  requestTimeoutMs?: number;
  /** TTL do `client_assertion` JWT em segundos (padrão 60; ≤0 usa o padrão). */
  assertionTtlSeconds?: number;
  /** Número máximo de tentativas em falha transitória (padrão 3; ≤0 usa o padrão). */
  maxRetries?: number;

  /** Habilita o cache de tokens por scope (padrão `true`). */
  enableTokenCache?: boolean;
  /** Margem em segundos para renovar token antes da expiração (padrão 30; ≤0 usa o padrão). */
  tokenCacheMarginSeconds?: number;
  /** Quantidade máxima de scopes retidos no cache (padrão 1000; deve ser positivo). */
  tokenCacheMaxEntries?: number;

  /** Logger opcional (ver {@link Logger}); se omitido, nada é logado. */
  logger?: Logger;
}

interface ClientContext {
  readonly tokenEndpoint: string;
  readonly clientId: string;
  readonly signingStrategy: SigningStrategy;
  readonly agent: https.Agent;
  readonly faultToleranceConfig: FaultToleranceConfig;
  readonly jwtAlgorithm: string;
  readonly keyId: string | undefined;
  readonly hubContext: HubContext | undefined;
  readonly mtlsConfigured: boolean;
  readonly logger: Logger;
  readonly sleep: (ms: number) => Promise<void>;
}

function defaultSleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function validateHubContext(hubContext: HubContext): void {
  if (!HUB_CTX_IG_PATTERN.test(hubContext.ig)) {
    throw new RangeError(
      `hub_ctx.ig inválido: '${hubContext.ig}' (use minúsculas, dígitos e hífen, iniciando por letra, 2 a 31 caracteres)`,
    );
  }
  if (!HUB_CTX_VERSAO_PATTERN.test(hubContext.versao)) {
    throw new RangeError(
      `hub_ctx.versao inválido: '${hubContext.versao}' (use SemVer completo MAJOR.MINOR.PATCH, ex.: 0.0.1)`,
    );
  }
}

function base64url(data: Uint8Array | string): string {
  return Buffer.from(data as never).toString("base64url");
}

async function buildClientAssertion(ctx: ClientContext): Promise<string> {
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + ctx.faultToleranceConfig.assertionTtlSeconds;
  const jti = randomUUID();

  const claims: Record<string, unknown> = {
    iss: ctx.clientId,
    sub: ctx.clientId,
    aud: ctx.tokenEndpoint,
    iat,
    exp,
    jti,
  };
  if (ctx.hubContext !== undefined) {
    claims.hub_ctx = { ig: ctx.hubContext.ig, versao: ctx.hubContext.versao };
  }

  const header: Record<string, unknown> = { alg: ctx.jwtAlgorithm, typ: "JWT" };
  if (ctx.keyId !== undefined && ctx.keyId.trim() !== "") {
    header.kid = ctx.keyId;
  }

  const headerB64 = base64url(JSON.stringify(header));
  const payloadB64 = base64url(JSON.stringify(claims));
  const dataToSign = `${headerB64}.${payloadB64}`;

  const signature = await ctx.signingStrategy(Buffer.from(dataToSign, "utf8"));
  return `${dataToSign}.${base64url(signature)}`;
}

function buildFormBody(clientId: string, assertion: string, scope: string): string {
  const params = new URLSearchParams();
  params.set("grant_type", GRANT_TYPE);
  params.set("client_id", clientId);
  params.set("client_assertion_type", ASSERTION_TYPE);
  params.set("client_assertion", assertion);
  if (scope !== "") {
    params.set("scope", scope);
  }
  return params.toString();
}

/**
 * Executa uma requisição HTTP(S), aplicando dois timeouts distintos
 * (RF-07): `connectTimeoutMs`, amarrado a um temporizador manual entre a
 * criação do socket e a conclusão da conexão — nem `http.Agent` nem
 * `https.Agent` têm uma opção de "connect timeout" própria (verificado
 * empiricamente: `Agent.options.timeout` é um timeout de *inatividade*
 * do socket, não uma janela de conexão) —, e `requestTimeoutMs`, via
 * `AbortSignal.timeout` cobrindo a requisição inteira (Node aceita
 * `signal` nativamente em `http(s).request` desde a v18, confirmado
 * empiricamente: o abort produz um `AbortError` com `code: "ABORT_ERR"`,
 * não `"TimeoutError"` como o `fetch` produzia).
 *
 * Sensível ao esquema da URL: `https:` usa `node:https` com o `agent`
 * TLS/mTLS configurado; `http:` usa `node:http` sem `agent` nenhum (só
 * possível para `localhost`/`127.0.0.1`, por força de `requireHttps` —
 * o `https.Agent` de mTLS não faz sentido nesse caso e nem é aceito por
 * `http.request`). Diferente do `undici.Agent` usado antes (que roteava
 * por esquema internamente, de forma transparente), `node:http` e
 * `node:https` são módulos e `Agent`s **separados** — não existe um
 * `Agent` único do Node que sirva para os dois esquemas.
 *
 * Ao estourar, o timeout de conexão é reportado com `code: "ETIMEDOUT"`
 * — o mesmo código que uma falha real de SO produziria — para que
 * {@link isTransientNetworkFailure} o reconheça sem precisar de um
 * código próprio.
 */
function requestWithConnectTimeout(
  url: string,
  options: { method: string; headers: Record<string, string | number>; signal: AbortSignal },
  agent: https.Agent,
  connectTimeoutMs: number,
  body?: string,
): Promise<IncomingMessage> {
  return new Promise((resolve, reject) => {
    const isHttps = new URL(url).protocol === "https:";
    const req = isHttps
      ? https.request(url, { ...options, agent }, resolve)
      : http.request(url, options, resolve);
    req.on("error", reject);

    const connectTimer = setTimeout(() => {
      const err = new Error(`Timeout de conexão (${connectTimeoutMs}ms) ao conectar em ${url}`);
      (err as NodeJS.ErrnoException).code = "ETIMEDOUT";
      req.destroy(err);
    }, connectTimeoutMs);
    const clearConnectTimer = (): void => clearTimeout(connectTimer);

    req.on("socket", (socket) => {
      if (!socket.connecting) {
        clearConnectTimer(); // socket reaproveitado (keep-alive), já conectado
        return;
      }
      socket.once(isHttps ? "secureConnect" : "connect", clearConnectTimer);
    });
    req.once("response", clearConnectTimer);
    req.once("error", clearConnectTimer);

    if (body !== undefined) {
      req.end(body);
    } else {
      req.end();
    }
  });
}

async function doObtainToken(scope: string, trace: TraceContext, ctx: ClientContext): Promise<RawTokenResponse> {
  const assertion = await buildClientAssertion(ctx);
  const body = buildFormBody(ctx.clientId, assertion, scope);

  const response = await requestWithConnectTimeout(
    ctx.tokenEndpoint,
    {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        "content-length": Buffer.byteLength(body),
        [TRACEPARENT_HEADER]: traceparent(trace),
      },
      signal: AbortSignal.timeout(ctx.faultToleranceConfig.requestTimeoutMs),
    },
    ctx.agent,
    ctx.faultToleranceConfig.connectTimeoutMs,
    body,
  );

  const bodyText = await readBoundedText(response);
  const statusCode = response.statusCode ?? 0;

  if (statusCode !== HTTP_OK) {
    throw httpFailure(statusCode, bodyText, response.headers["retry-after"] ?? null, trace.traceId, ctx.logger);
  }

  const parsed: unknown = JSON.parse(bodyText);
  const accessToken =
    typeof parsed === "object" && parsed !== null && "access_token" in parsed
      ? (parsed as Record<string, unknown>).access_token
      : undefined;
  if (typeof accessToken !== "string") {
    throw new SmartTokenError("Resposta não contém 'access_token'");
  }

  const expiresIn = sanitizeExpiresIn(parsed, ctx.logger);
  return { accessToken, expiresIn, rawJson: bodyText };
}

async function fetchTokenWithRetry(scope: string, ctx: ClientContext): Promise<RawTokenResponse> {
  const maxRetries = ctx.faultToleranceConfig.maxRetries;
  let lastError: unknown;
  let lastTraceId = "n/d";

  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    const trace = generateTraceContext();
    lastTraceId = trace.traceId;
    try {
      return await doObtainToken(scope, trace, ctx);
    } catch (err) {
      if (isConfirmedClientCertificateRejection(err, ctx.mtlsConfigured)) {
        // RF-08.1: alerta TLS confirmado do servidor — falha imediata, sem retry.
        throw new SmartTokenError(
          `Servidor rejeitou o certificado de cliente (mTLS), sem novas tentativas ` +
            `(traceId=${trace.traceId}): ${err instanceof Error ? err.message : String(err)}`,
          err,
        );
      }
      if (!isTransientNetworkFailure(err)) {
        throw err;
      }
      lastError = err;
    }
    if (attempt < maxRetries) {
      const delayMs = computeRetryDelayMs(attempt);
      ctx.logger.warn?.(`Tentativa ${attempt}/${maxRetries} falhou: retry em ${delayMs}ms`, {
        traceId: lastTraceId,
      });
      await ctx.sleep(delayMs);
    } else {
      ctx.logger.error?.(`Todas as ${maxRetries} tentativas falharam`, { traceId: lastTraceId });
    }
  }

  const hint = isLikelyClientCertificateRejection(lastError, ctx.mtlsConfigured)
    ? " Possível causa: certificado de cliente rejeitado pelo servidor (mTLS) — verifique sua " +
      "validade; também pode ser apenas instabilidade de rede."
    : "";
  throw new SmartTokenError(
    `Falha após ${maxRetries} tentativas (último traceId=${lastTraceId}): ` +
      `${lastError instanceof Error ? lastError.message : "sem causa capturada"}${hint}`,
    lastError,
  );
}

/**
 * Cliente HubSaúde para obtenção de access tokens SMART Backend Services.
 *
 * Abstrai a montagem e assinatura do `client_assertion` JWT, a
 * comunicação HTTP com o token endpoint, cache por scope,
 * *single-flight* e retry com backoff exponencial.
 *
 * A instância é reutilizável durante o ciclo de vida da aplicação —
 * construa uma vez (via {@link createSmartTokenClient}) e chame
 * {@link close} apenas no encerramento. Não há construtor público: use
 * sempre {@link createSmartTokenClient}.
 */
/**
 * Token de construção privado ao módulo — nunca exportado, portanto
 * impossível de obter fora deste arquivo.
 *
 * O `private` do TypeScript sozinho **não impede** `new SmartTokenClient(...)`
 * em runtime: é só uma checagem do compilador, apagada no JavaScript
 * gerado — qualquer código (TS com um cast, ou JavaScript puro sem
 * passar pelo `tsc`) consegue chamar o construtor livremente se nada
 * mais o impedir. Este símbolo fecha essa lacuna: sem ele, o
 * construtor lança um erro explícito.
 */
const CONSTRUCTION_GUARD = Symbol("SmartTokenClient.constructionGuard");

export class SmartTokenClient {
  readonly #context: ClientContext;
  readonly #tokenCache: TokenCacheStrategy;
  readonly #pending = new Set<Promise<unknown>>();
  #closed = false;

  private constructor(guard: symbol, context: ClientContext, tokenCache: TokenCacheStrategy) {
    if (guard !== CONSTRUCTION_GUARD) {
      throw new Error("SmartTokenClient não tem construtor público; use createSmartTokenClient(options)");
    }
    this.#context = context;
    this.#tokenCache = tokenCache;
  }

  /**
   * Constrói um {@link SmartTokenClient} a partir das opções informadas.
   * Único ponto de construção (não há construtor público) — chamado
   * pela função de nível superior {@link createSmartTokenClient}.
   *
   * @param options - configuração do cliente
   * @param sleep - função de espera usada no backoff entre tentativas.
   *   **Não faz parte da API pública** — parâmetro à parte de
   *   `options` (não um campo dela) exatamente para não aparecer na
   *   superfície pensada para uso normal; existe só para os testes
   *   deste repositório injetarem uma espera determinística, sem
   *   esperar segundos reais. Equivalente ao `Sleeper` package-private
   *   do Java — a mesma ressalva vale aqui: como qualquer restrição de
   *   visibilidade, desencoraja uso casual/acidental, mas não é uma
   *   barreira à prova de quem decidir contornar de propósito (assim
   *   como o Java também não é, via reflection).
   * @returns o cliente pronto para uso
   * @throws {Error} se a configuração obrigatória estiver incompleta ou
   *   inconsistente (RF-18)
   * @throws {RangeError} se algum valor estiver fora do intervalo
   *   aceito (URL insegura, chave fraca, `hub_ctx` malformado)
   * @throws {SmartTokenError} se o carregamento de PEM/PKCS#12 ou a
   *   descoberta do endpoint falharem
   */
  static async create(
    options: SmartTokenClientOptions,
    sleep: (ms: number) => Promise<void> = defaultSleep,
  ): Promise<SmartTokenClient> {
    const hasTokenEndpoint = options.tokenEndpoint !== undefined;
    const hasFhirBase = options.fhirBase !== undefined;
    if (hasTokenEndpoint === hasFhirBase) {
      throw new Error("Defina exatamente um entre tokenEndpoint e fhirBase");
    }
    if (options.clientId === undefined || options.clientId === "") {
      throw new Error("clientId é obrigatório");
    }
    if (hasTokenEndpoint) {
      requireHttps(options.tokenEndpoint as string, "tokenEndpoint");
    } else {
      requireHttps(options.fhirBase as string, "fhirBase");
    }

    const hasStrategy = options.signingStrategy !== undefined;
    const hasPem = options.privateKeyPem !== undefined;
    if (hasStrategy === hasPem) {
      throw new Error("Defina exatamente um entre signingStrategy e privateKeyPem");
    }

    const jwtAlgorithm = options.jwtAlgorithm ?? DEFAULT_JWT_ALGORITHM;
    jwtAlgorithmToNode(jwtAlgorithm); // valida contra a allowlist (fail-fast)

    if (options.hubContext !== undefined) {
      validateHubContext(options.hubContext);
    }

    const tokenCacheMaxEntries = options.tokenCacheMaxEntries ?? 1000;
    if (tokenCacheMaxEntries <= 0) {
      throw new RangeError(`tokenCacheMaxEntries deve ser positivo: ${tokenCacheMaxEntries}`);
    }

    let signingStrategy: SigningStrategy;
    let clientKey: KeyObject | undefined;
    if (hasStrategy) {
      signingStrategy = options.signingStrategy as SigningStrategy;
    } else {
      clientKey = await loadPrivateKey(options.privateKeyPem as string, options.privateKeyPassword);
      signingStrategy = fromPrivateKeyForJwt(clientKey, jwtAlgorithm);
    }

    const clientCertificate =
      options.certificatePem !== undefined ? await loadCertificate(options.certificatePem) : undefined;

    const faultToleranceConfig = resolveFaultToleranceConfig(options as FaultToleranceOptions);

    const tlsMaterial: TlsMaterial = {
      tlsProtocol: options.tlsProtocol,
    };
    if (options.serverTrustAnchor !== undefined) {
      tlsMaterial.serverTrustAnchor = (await loadCertificate(options.serverTrustAnchor)).toString();
    }
    let mtlsConfigured = false;
    if (options.clientPfx !== undefined) {
      tlsMaterial.clientPfx = options.clientPfx;
      tlsMaterial.clientPfxPassphrase = options.clientPfxPassphrase;
      mtlsConfigured = true;
    } else if (clientKey !== undefined && clientCertificate !== undefined) {
      tlsMaterial.clientKey = clientKey;
      tlsMaterial.clientCertificate = clientCertificate;
      mtlsConfigured = true;
      verifyKeyPair(clientKey, clientCertificate);
    }
    if (clientCertificate !== undefined) {
      checkCertificateValidity(clientCertificate, options.certificatePem ?? "<certificatePem>");
    }

    const agent = buildAgent(tlsMaterial);

    const tokenEndpoint = hasTokenEndpoint
      ? (options.tokenEndpoint as string)
      : await discoverTokenEndpoint(options.fhirBase as string, agent, faultToleranceConfig.connectTimeoutMs);

    const context: ClientContext = {
      tokenEndpoint,
      clientId: options.clientId,
      signingStrategy,
      agent,
      faultToleranceConfig,
      jwtAlgorithm,
      keyId: options.keyId,
      hubContext: options.hubContext,
      mtlsConfigured,
      logger: options.logger ?? NOOP_LOGGER,
      sleep,
    };

    const tokenCache = new TokenCacheStrategy({
      enabled: options.enableTokenCache ?? true,
      marginSeconds: options.tokenCacheMarginSeconds,
      maxEntries: tokenCacheMaxEntries,
      logger: options.logger,
    });

    return new SmartTokenClient(CONSTRUCTION_GUARD, context, tokenCache);
  }

  /**
   * Obtém um access token para os scopes informados.
   *
   * Se o cache estiver habilitado, tokens válidos são reutilizados; a
   * renovação ocorre automaticamente quando o token está próximo de
   * expirar (margem configurável). Em falha transitória de rede,
   * tenta de novo com backoff exponencial; respostas HTTP recebidas
   * (qualquer status) não sofrem retry automático.
   *
   * @param scope - scopes separados por espaço (ex.: `"system/Patient.rs"`)
   * @returns o access token emitido pelo servidor de autorização
   */
  async obtainToken(scope?: string): Promise<string> {
    return (await this.obtainTokenResponse(scope)).accessToken;
  }

  /**
   * Obtém um token de acesso e devolve a resposta completa do servidor,
   * incluindo o corpo JSON cru (quando obtido por uma requisição real —
   * `rawJson` é `null` quando servido do cache).
   *
   * @param scope - scopes separados por espaço (ex.: `"system/Patient.rs"`)
   * @returns a resposta do token endpoint
   */
  async obtainTokenResponse(scope?: string): Promise<TokenResponse> {
    this.#ensureOpen();
    const normalizedScope = scope === undefined || scope === null ? "" : scope.trim();
    const operation = this.#tokenCache.getOrFetch(normalizedScope, () =>
      fetchTokenWithRetry(normalizedScope, this.#context),
    );
    this.#pending.add(operation);
    try {
      return await operation;
    } finally {
      this.#pending.delete(operation);
    }
  }

  /** Invalida o cache de tokens, forçando nova obtenção na próxima chamada. */
  invalidateCache(scope?: string): void {
    if (scope === undefined) {
      this.#tokenCache.invalidateAll();
      return;
    }
    this.#tokenCache.invalidate(scope.trim());
  }

  /** URL do token endpoint efetivo (inclusive quando descoberto via `fhirBase`). */
  getTokenEndpoint(): string {
    return this.#context.tokenEndpoint;
  }

  /** Algoritmo JWT configurado para assinatura do `client_assertion`. */
  getJwtAlgorithm(): string {
    return this.#context.jwtAlgorithm;
  }

  /** Identificador de chave (`kid`) configurado, ou `undefined`. */
  getKeyId(): string | undefined {
    return this.#context.keyId;
  }

  /**
   * Fecha o cliente: aguarda operações em voo, encerra o `https.Agent`
   * interno, invalida o cache e — se a `signingStrategy` configurada
   * tiver um método `close` (ver {@link CloseableSigningStrategy}, ex.:
   * a sessão PKCS#11 aberta por {@link fromPkcs11}) — libera esse
   * recurso também. Idempotente — chamadas subsequentes não têm efeito.
   * Após o fechamento, `obtainToken`/`obtainTokenResponse` falham
   * explicitamente.
   */
  async close(): Promise<void> {
    if (this.#closed) {
      return;
    }
    this.#closed = true;
    await Promise.allSettled([...this.#pending]);
    this.#context.agent.destroy();
    this.#tokenCache.invalidateAll();
    await (this.#context.signingStrategy as CloseableSigningStrategy).close?.();
  }

  /** Permite `await using client = await createSmartTokenClient(...)`. */
  async [Symbol.asyncDispose](): Promise<void> {
    await this.close();
  }

  #ensureOpen(): void {
    if (this.#closed) {
      throw new Error("SmartTokenClient já foi fechado");
    }
  }
}

/**
 * Constrói um {@link SmartTokenClient} a partir das opções informadas.
 *
 * Substitui o builder fluente do Java: função fábrica assíncrona (a
 * construção envolve I/O — leitura de PEM e, opcionalmente, descoberta
 * do endpoint via rede) recebendo um único objeto de opções. Ponto de
 * entrada recomendado — equivalente a {@link SmartTokenClient.create}.
 *
 * @param options - configuração do cliente
 * @returns o cliente pronto para uso
 * @throws {Error} se a configuração obrigatória estiver incompleta ou
 *   inconsistente (RF-18)
 * @throws {RangeError} se algum valor estiver fora do intervalo aceito
 *   (URL insegura, chave fraca, `hub_ctx` malformado)
 * @throws {SmartTokenError} se o carregamento de PEM/PKCS#12 ou a
 *   descoberta do endpoint falharem
 */
export async function createSmartTokenClient(options: SmartTokenClientOptions): Promise<SmartTokenClient> {
  return SmartTokenClient.create(options);
}
