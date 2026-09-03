// O modo padrão do Stryker (sandbox: copia o projeto pra um diretório
// temporário antes de mutar) não funciona com `typescript@7.x` — seu
// pré-processador interno chama `ts.parseConfigFileTextToJson`, uma API
// removida/renomeada no compilador do TS 7. `npm run test:mutation` usa
// `--inPlace` para contornar isso: muta os arquivos reais temporariamente
// (o próprio Stryker faz backup e restaura ao final). Remover `--inPlace`
// assim que o Stryker suportar TS 7.x.
/** @type {import('@stryker-mutator/api/core').PartialStrykerOptions} */
export default {
  packageManager: "npm",
  testRunner: "vitest",
  reporters: ["clear-text", "progress", "html"],
  coverageAnalysis: "perTest",
  mutate: ["src/**/*.ts", "!src/**/*.d.ts"],
  htmlReporter: {
    fileName: "reports/mutation/index.html",
  },
};
