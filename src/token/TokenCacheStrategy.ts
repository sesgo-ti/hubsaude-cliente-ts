/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import { NOOP_LOGGER, type Logger } from "../logging/Logger.js";

/** Quantidade máxima padrão de scopes retidos no cache de tokens. */
export const DEFAULT_TOKEN_CACHE_MAX_ENTRIES = 1_000;

/** Margem padrão em segundos para renovar token antes da expiração. */
export const DEFAULT_TOKEN_CACHE_MARGIN_SECONDS = 30;

/** Resposta do token endpoint (formato interno, antes de virar {@link TokenResponse} pública). */
export interface RawTokenResponse {
  accessToken: string;
  expiresIn: number;
  rawJson?: string | null;
}

/** Resposta pronta para o chamador: token, tempo restante e o corpo cru (quando disponível). */
export interface TokenResponse {
  readonly accessToken: string;
  readonly expiresIn: number;
  readonly rawJson: string | null;
}

interface CachedToken {
  accessToken: string;
  expiresAtMs: number;
}

export interface TokenCacheStrategyOptions {
  enabled?: boolean;
  marginSeconds?: number;
  maxEntries?: number;
  /** Fonte de tempo, substituível para testes determinísticos (equivalente ao `Clock` do Java). */
  now?: () => number;
  logger?: Logger;
}

/**
 * Cache de tokens por scope com deduplicação de requisições concorrentes
 * (single-flight) e janela LRU de tamanho fixo.
 *
 * Diferente do Java — que precisa de *lock striping* porque múltiplas
 * threads do SO podem competir de verdade pelo mesmo scope —, o Node
 * roda num único event loop: a deduplicação aqui é feita guardando a
 * `Promise` em voo por scope (`Map<scope, Promise>`), conforme a própria
 * especificação recomenda (§9.4) para plataformas de I/O assíncrono de
 * thread única. O "double-check" que o Java faz explicitamente dentro do
 * lock também não é necessário aqui: como nada mais executa entre a
 * checagem do cache e a criação da promessa (não há `await` nesse meio),
 * não existe janela de corrida a fechar.
 */
export class TokenCacheStrategy {
  private readonly enabled: boolean;
  private readonly marginSeconds: number;
  private readonly maxEntries: number;
  private readonly now: () => number;
  private readonly logger: Logger;
  private readonly cache = new Map<string, CachedToken>();
  private readonly inFlight = new Map<string, Promise<TokenResponse>>();

  constructor(options: TokenCacheStrategyOptions = {}) {
    const maxEntries = options.maxEntries ?? DEFAULT_TOKEN_CACHE_MAX_ENTRIES;
    if (maxEntries <= 0) {
      throw new RangeError(`maxEntries deve ser positivo: ${maxEntries}`);
    }
    this.enabled = options.enabled ?? true;
    this.marginSeconds =
      options.marginSeconds !== undefined && options.marginSeconds > 0
        ? options.marginSeconds
        : DEFAULT_TOKEN_CACHE_MARGIN_SECONDS;
    this.maxEntries = maxEntries;
    this.now = options.now ?? Date.now;
    this.logger = options.logger ?? NOOP_LOGGER;
  }

  /**
   * Obtém um token válido do cache para o scope, ou executa `fetcher`
   * (deduplicando chamadas concorrentes para o mesmo scope) e armazena
   * o resultado.
   *
   * @param normalizedScope - scope já normalizado (trim; `null` → `""`)
   * @param fetcher - função que obtém um token novo do servidor,
   *   incluindo qualquer retry — chamada no máximo uma vez por scope
   *   enquanto houver uma chamada em voo
   * @returns a resposta do token, do cache ou recém-obtida
   */
  async getOrFetch(normalizedScope: string, fetcher: () => Promise<RawTokenResponse>): Promise<TokenResponse> {
    if (this.enabled) {
      const cached = this.cachedResponseIfValid(normalizedScope);
      if (cached !== undefined) {
        this.logger.debug?.("Retornando token em cache", { scope: normalizedScope });
        return cached;
      }
      const pending = this.inFlight.get(normalizedScope);
      if (pending !== undefined) {
        return pending;
      }
    }

    const promise = fetcher()
      .then((raw) => {
        const response: TokenResponse = {
          accessToken: raw.accessToken,
          expiresIn: raw.expiresIn,
          rawJson: raw.rawJson ?? null,
        };
        if (this.enabled) {
          this.store(normalizedScope, raw);
        }
        return response;
      })
      .finally(() => this.inFlight.delete(normalizedScope));

    if (this.enabled) {
      this.inFlight.set(normalizedScope, promise);
    }
    return promise;
  }

  /**
   * Retorna o token em cache para o scope, se habilitado e ainda
   * válido (com margem); caso contrário, `undefined`.
   */
  private cachedResponseIfValid(normalizedScope: string): TokenResponse | undefined {
    const cached = this.cache.get(normalizedScope);
    if (cached === undefined) {
      return undefined;
    }
    const stillValid = this.now() + this.marginSeconds * 1000 < cached.expiresAtMs;
    if (!stillValid) {
      this.cache.delete(normalizedScope);
      return undefined;
    }
    // Reinsere para marcar como recentemente usado (ordem de acesso, estilo LRU).
    this.cache.delete(normalizedScope);
    this.cache.set(normalizedScope, cached);
    const remainingSeconds = Math.max(0, Math.round((cached.expiresAtMs - this.now()) / 1000));
    return { accessToken: cached.accessToken, expiresIn: remainingSeconds, rawJson: null };
  }

  private store(normalizedScope: string, response: RawTokenResponse): void {
    this.cache.set(normalizedScope, {
      accessToken: response.accessToken,
      expiresAtMs: this.now() + response.expiresIn * 1000,
    });
    if (this.cache.size > this.maxEntries) {
      const oldestKey = this.cache.keys().next().value;
      if (oldestKey !== undefined) {
        this.cache.delete(oldestKey);
      }
    }
    this.logger.debug?.("Token cacheado", { scope: normalizedScope, expiresIn: response.expiresIn });
  }

  /** Invalida o cache de tokens de todos os scopes. */
  invalidateAll(): void {
    this.cache.clear();
    this.logger.info?.("Cache de tokens invalidado");
  }

  /** Invalida o cache para um scope específico. */
  invalidate(normalizedScope: string): void {
    this.cache.delete(normalizedScope);
    this.logger.info?.("Cache invalidado", { scope: normalizedScope });
  }

  /** Quantidade de entradas retidas no momento (para testes/diagnóstico). */
  size(): number {
    return this.cache.size;
  }
}
