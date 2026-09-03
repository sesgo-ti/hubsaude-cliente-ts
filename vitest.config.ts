import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    // "it/**" fica de fora do include-padrão do vitest (que casa
    // qualquer "*.test.ts" no repo, não só em "test/**"): são testes de
    // integração reais contra o simulador local do HubSaúde (CLI
    // `hubsaude`), fisicamente separados de "test/**" de propósito, e
    // não devem rodar como parte de "npm test"/"npm run test:coverage".
    // Rodam só via "npm run test:integration", que usa
    // `vitest.integration.config.ts` — uma configuração à parte (sem
    // este exclude) dedicada a "it/**".
    exclude: ["node_modules/**", "dist/**", "it/**"],
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
