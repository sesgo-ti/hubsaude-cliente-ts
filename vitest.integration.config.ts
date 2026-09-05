import { defineConfig } from "vitest/config";

/**
 * Configuração dedicada aos testes de integração reais em
 * `test/integration/` (contra o simulador local do HubSaúde via CLI
 * `hubsaude`, ou o ambiente de homologação real — ver
 * `test/integration/SmartTokenClientSimulador.test.ts` e
 * `test/integration/SmartTokenClientHomolog.test.ts`).
 *
 * Deliberadamente separada de `vitest.config.ts`: o `vitest run`
 * padrão (usado por `npm test`/`npm run test:coverage`) precisa
 * excluir `test/integration/**` para nunca rodar estes testes sem
 * querer — e, com esse caminho excluído ali, um único arquivo de
 * configuração compartilhado não conseguiria também servir de include
 * para `npm run test:integration`. Só é usada explicitamente por esse
 * script, nunca carregada implicitamente por `vitest`/`vitest run` sem
 * `--config`.
 */
export default defineConfig({
  test: {
    include: ["test/integration/**/*.test.ts"],
    exclude: ["node_modules/**", "dist/**"],
  },
});
