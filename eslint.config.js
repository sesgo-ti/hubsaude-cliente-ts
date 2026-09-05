// @ts-check
import js from "@eslint/js";
import security from "eslint-plugin-security";
import prettierConfig from "eslint-config-prettier";

// `typescript-eslint` 8.x recusa carregar contra `typescript@7.x` (este
// projeto usa `typescript@^7.0.2`) — o próprio pacote lança
// "typescript-eslint does not support TS 7.0" na importação do módulo;
// ver github.com/typescript-eslint/typescript-eslint/issues/10940, ainda
// sem suporte a TS >=7.1 no momento em que isto foi escrito. Isso
// bloqueia tanto o parser quanto o plugin de regras — não é algo
// contornável por configuração, é uma checagem de versão no próprio
// pacote.
//
// Solução interina: `@babel/eslint-parser` + `@babel/preset-typescript`
// parseiam a sintaxe TypeScript sem depender do compilador `typescript`
// de forma alguma (o parser do Babel implementa a gramática TS por conta
// própria) — então nenhuma regra do `@typescript-eslint/eslint-plugin`
// está disponível aqui (essas regras dependem da forma específica de AST
// que o parser oficial do typescript-eslint produz), só as regras
// genéricas de `@eslint/js` e `eslint-plugin-security` aplicadas por
// cima da sintaxe TS já interpretada. Voltar a usar `typescript-eslint`
// assim que ele suportar TS 7.x, ou se o projeto decidir fixar uma
// versão de `typescript` <6.1 só para esta ferramenta.
export default [
  {
    ignores: ["dist/**", "coverage/**", "node_modules/**", "reports/**", ".stryker-tmp/**"],
  },
  js.configs.recommended,
  {
    files: ["**/*.ts"],
    languageOptions: {
      parser: (await import("@babel/eslint-parser")).default,
      parserOptions: {
        requireConfigFile: false,
        babelOptions: {
          presets: ["@babel/preset-typescript"],
        },
      },
    },
    rules: {
      "no-unused-vars": "off", // sem informação de tipo, gera falso-positivo em overloads/generics
      "no-undef": "off", // tipos TS (interfaces, type aliases) não são "globais" reais; o próprio tsc já cobre isso
    },
  },
  security.configs.recommended,
  {
    // Os testes leem/escrevem arquivos dentro de diretórios temporários
    // criados por `mkdtemp` (API segura do próprio Node) e indexam
    // arrays com tipos literais restritos (ex.: `0 | 1 | 2`) — não
    // "entrada não confiável" no sentido que essas duas regras existem
    // para prevenir. Falso-positivo conhecido e frequente do
    // `eslint-plugin-security` em código de teste; ver também os
    // `eslint-disable-next-line` pontuais em `src/` para os casos
    // equivalentes fora de teste, tratados individualmente em vez de
    // desligados por categoria. Cobre também `test/integration/` (testes
    // de integração reais, mesmo perfil de acesso a arquivo).
    files: ["test/**/*.ts"],
    rules: {
      "security/detect-non-literal-fs-filename": "off",
      "security/detect-object-injection": "off",
    },
  },
  prettierConfig,
];
