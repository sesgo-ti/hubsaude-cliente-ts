import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // "test/integration/**" são testes de integração reais contra o
    // simulador local do HubSaúde (CLI `hubsaude`) ou o ambiente de
    // homologação real — não devem rodar como parte de "npm
    // test"/"npm run test:coverage". Rodam só via "npm run
    // test:integration"/"npm run test:integration:homolog", que usam
    // `vitest.integration.config.ts` — uma configuração à parte (sem
    // este exclude) dedicada a "test/integration/**".
    exclude: ["node_modules/**", "dist/**", "test/integration/**"],
    coverage: {
      provider: "v8",
      reporter: ["text", "html", "lcov"],
      include: ["src/**/*.ts"],
      exclude: ["src/**/*.d.ts"],
      // RNF-06: cobertura mínima de linha de 85%, como gate.
      thresholds: {
        lines: 85,
      },
    },
  },
});
