import { describe, expect, it } from "vitest";
import { TokenCacheStrategy } from "../../src/token/TokenCacheStrategy.js";

function fakeClock(startMs = 0) {
  let now = startMs;
  return { now: () => now, advance: (ms: number) => (now += ms) };
}

describe("TokenCacheStrategy", () => {
  it("lança RangeError para maxEntries não positivo", () => {
    expect(() => new TokenCacheStrategy({ maxEntries: 0 })).toThrow(RangeError);
    expect(() => new TokenCacheStrategy({ maxEntries: -1 })).toThrow(RangeError);
  });

  it("serve do cache dentro da validade, sem chamar o fetcher de novo", async () => {
    const clock = fakeClock();
    const cache = new TokenCacheStrategy({ now: clock.now });
    let calls = 0;
    const fetcher = async () => {
      calls++;
      return { accessToken: "tok-1", expiresIn: 60 };
    };

    const first = await cache.getOrFetch("scope-a", fetcher);
    const second = await cache.getOrFetch("scope-a", fetcher);

    expect(first.accessToken).toBe("tok-1");
    expect(second.accessToken).toBe("tok-1");
    expect(calls).toBe(1);
  });

  it("busca de novo após expirar a margem", async () => {
    const clock = fakeClock();
    const cache = new TokenCacheStrategy({ now: clock.now, marginSeconds: 10 });
    let calls = 0;
    const fetcher = async () => {
      calls++;
      return { accessToken: `tok-${calls}`, expiresIn: 60 };
    };

    await cache.getOrFetch("scope-a", fetcher);
    clock.advance(55_000); // passou de 60s - 10s de margem = 50s
    const second = await cache.getOrFetch("scope-a", fetcher);

    expect(calls).toBe(2);
    expect(second.accessToken).toBe("tok-2");
  });

  it("trata scopes distintos de forma independente", async () => {
    const cache = new TokenCacheStrategy();
    const fetcherA = async () => ({ accessToken: "a", expiresIn: 60 });
    const fetcherB = async () => ({ accessToken: "b", expiresIn: 60 });

    const a = await cache.getOrFetch("scope-a", fetcherA);
    const b = await cache.getOrFetch("scope-b", fetcherB);

    expect(a.accessToken).toBe("a");
    expect(b.accessToken).toBe("b");
  });

  it("deduplica chamadas concorrentes para o mesmo scope (single-flight)", async () => {
    const cache = new TokenCacheStrategy();
    let calls = 0;
    let resolveFetch: (value: { accessToken: string; expiresIn: number }) => void;
    const fetcher = () => {
      calls++;
      return new Promise<{ accessToken: string; expiresIn: number }>((resolve) => {
        resolveFetch = resolve;
      });
    };

    const p1 = cache.getOrFetch("scope-a", fetcher);
    const p2 = cache.getOrFetch("scope-a", fetcher);
    resolveFetch!({ accessToken: "tok", expiresIn: 60 });
    const [r1, r2] = await Promise.all([p1, p2]);

    expect(calls).toBe(1);
    expect(r1.accessToken).toBe("tok");
    expect(r2.accessToken).toBe("tok");
  });

  it("com cache desabilitado, sempre chama o fetcher", async () => {
    const cache = new TokenCacheStrategy({ enabled: false });
    let calls = 0;
    const fetcher = async () => {
      calls++;
      return { accessToken: "tok", expiresIn: 60 };
    };

    await cache.getOrFetch("scope-a", fetcher);
    await cache.getOrFetch("scope-a", fetcher);

    expect(calls).toBe(2);
  });

  it("invalidateAll limpa todos os scopes", async () => {
    const cache = new TokenCacheStrategy();
    await cache.getOrFetch("scope-a", async () => ({ accessToken: "a", expiresIn: 60 }));
    await cache.getOrFetch("scope-b", async () => ({ accessToken: "b", expiresIn: 60 }));
    expect(cache.size()).toBe(2);

    cache.invalidateAll();

    expect(cache.size()).toBe(0);
  });

  it("invalidate limpa só o scope informado", async () => {
    const cache = new TokenCacheStrategy();
    await cache.getOrFetch("scope-a", async () => ({ accessToken: "a", expiresIn: 60 }));
    await cache.getOrFetch("scope-b", async () => ({ accessToken: "b", expiresIn: 60 }));

    cache.invalidate("scope-a");

    expect(cache.size()).toBe(1);
  });

  it("descarta a entrada menos recentemente usada ao atingir o teto (LRU)", async () => {
    const cache = new TokenCacheStrategy({ maxEntries: 2 });
    const fetcherFor = (token: string) => async () => ({ accessToken: token, expiresIn: 60 });

    await cache.getOrFetch("scope-1", fetcherFor("t1"));
    await cache.getOrFetch("scope-2", fetcherFor("t2"));
    await cache.getOrFetch("scope-3", fetcherFor("t3")); // deve descartar scope-1

    expect(cache.size()).toBe(2);
    let calls = 0;
    await cache.getOrFetch("scope-1", async () => {
      calls++;
      return { accessToken: "t1-novo", expiresIn: 60 };
    });
    expect(calls).toBe(1); // precisou buscar de novo: scope-1 não estava mais em cache
  });

  it("informa o tempo restante ao servir do cache", async () => {
    const clock = fakeClock();
    const cache = new TokenCacheStrategy({ now: clock.now, marginSeconds: 5 });
    await cache.getOrFetch("scope-a", async () => ({ accessToken: "tok", expiresIn: 100 }));

    clock.advance(40_000);
    const result = await cache.getOrFetch("scope-a", async () => {
      throw new Error("não deveria chamar o fetcher de novo");
    });

    expect(result.expiresIn).toBe(60);
    expect(result.rawJson).toBeNull();
  });
});
