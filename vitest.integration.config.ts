import { defineConfig } from "vitest/config";

/**
 * Configuração dedicada aos testes de integração reais em `it/`
 * (contra o simulador local do HubSaúde via CLI `hubsaude` — ver
 * `it/SmartTokenClientSimulador.test.ts`).
 *
 * Deliberadamente separada de `vitest.config.ts`: o `vitest run`
 * padrão (usado por `npm test`/`npm run test:coverage`) precisa
 * excluir `it/**` para nunca rodar estes testes sem querer — e, com
 * `it/**` excluído ali, um único arquivo de configuração compartilhado
 * não conseguiria também servir de include para `npm run
 * test:integration`. Só é usada explicitamente por esse script, nunca
 * carregada implicitamente por `vitest`/`vitest run` sem `--config`.
 */
export default defineConfig({
  test: {
    include: ["it/**/*.test.ts"],
    exclude: ["node_modules/**", "dist/**"],
  },
});
