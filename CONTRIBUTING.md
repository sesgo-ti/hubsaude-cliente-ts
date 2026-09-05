# Como contribuir com hubsaude-cliente-js

Obrigado pelo interesse em contribuir! Este documento descreve o processo
padronizado de contribuição para o SDK TypeScript/Node.js do HubSaúde.

## Código de conduta

Toda interação está sujeita ao [Código de Conduta](CODE_OF_CONDUCT.md),
baseado no Contributor Covenant 2.1.

## Licença das contribuições

Ao submeter um Pull Request, você concorda em licenciar sua contribuição
sob a **Apache License 2.0**, a mesma licença deste projeto. Veja
[LICENSE](LICENSE).

## Developer Certificate of Origin (DCO)

Este projeto adota o [Developer Certificate of Origin 1.1](https://developercertificate.org/).
Toda contribuição precisa ter `Signed-off-by:` em cada commit.

Assine automaticamente:

```bash
git commit -s -m "feat: minha alteração"
```

Isso adiciona ao corpo da mensagem:

```
Signed-off-by: Seu Nome <seu@email.com>
```

Esse trailer atesta que você tem direito de submeter o trabalho sob a
licença do projeto, conforme o texto integral do DCO. Commits sem
`Signed-off-by:` serão bloqueados pelo CI.

## Fluxo de contribuição

1. **Issue primeiro**: abra ou comente em uma issue descrevendo o problema
   ou a feature.
2. **Fork e branch**: trabalhe em branch dedicado a partir de `develop`.
   Nome sugerido: `feat/curto-descritivo`, `fix/issue-123`, `docs/...`.
3. **Conventional Commits**:
   - `feat:` nova funcionalidade
   - `fix:` correção de bug
   - `docs:` documentação
   - `refactor:`, `test:`, `chore:`, `perf:`, `build:`, `ci:`
4. **Testes obrigatórios**: toda mudança de comportamento exige teste novo
   ou atualização do existente. Cobertura é monitorada via
   `@vitest/coverage-v8` (mínimo de 85% de linha, configurado como gate em
   `vitest.config.ts`).
5. **Build verde** localmente antes de abrir PR:
   ```bash
   npm ci
   npm run typecheck
   npm test
   npm run test:coverage
   ```
   Rode também as verificações de qualidade estática, mantidas como parte
   do fluxo normal de contribuição (não apenas opcionais):
   ```bash
   npm run lint
   npm run format:check
   npm run depcruise
   ```
6. **PR pequeno e focado**: prefira PRs de até ~400 linhas modificadas.
7. **Descrição do PR**: explique _o quê_, _por quê_ e _como testar_.
   Referencie issues com `Closes #123`.

## Padrões técnicos

- **Node.js 22+** (`engines.node` do `package.json`). Build e testes via
  **npm**.
- **TypeScript** como linguagem de implementação; a API pública é
  consumível também a partir de JavaScript puro (ver `exports` do
  `package.json`).
- **Formatação**: Prettier (`.prettierrc.json`) — `npm run format` corrige,
  `npm run format:check` só verifica. Não reformate arquivos fora do
  escopo do seu PR.
- **Lint**: ESLint (`eslint.config.js`), com `eslint-plugin-security` para
  padrões arriscados (ex.: `eval`, caminho de arquivo não literal). O
  topo de `eslint.config.js` documenta uma limitação atual conhecida:
  `typescript-eslint` ainda não suporta a versão de `typescript` usada
  neste projeto, então as regras específicas de TypeScript não estão
  ativas por enquanto — não desligue essa observação nem tente
  "corrigir" contornando-a sem entender o motivo.
- **JSDoc/TSDoc** em pt-BR para toda a API pública exportada pelo ponto de
  entrada do pacote. Comentários devem ser escritos para quem vai
  **integrar** a lib — descreva comportamento e motivo, não anotações de
  processo interno de desenvolvimento. Geração de documentação via
  TypeDoc ainda não está disponível — bloqueada por incompatibilidade
  com `typescript@^7.0.2` (ver seção "Documentação de API" no
  `README.md`); mantenha o JSDoc completo mesmo assim, já que ele
  também é lido diretamente do código-fonte.
- **Sem `console.log`/`console.error`** na biblioteca: use o `logger`
  injetável opcional (`logging/Logger.ts`) nos pontos de código que já o
  recebem. A lib não deve impor nenhuma infraestrutura de log ao
  integrador.
- **Imutabilidade preferida** onde a API o permitir (evite mutar objetos
  de opções recebidos do chamador).
- **Regras de arquitetura** (`dependency-cruiser`, `.dependency-cruiser.mjs`)
  são bloqueantes: sem dependência circular em `src/`, e módulos de apoio
  (`errors`, `signing`, `tls`, `resilience`, `token`, `trace`, `logging`)
  não podem importar de `client/` — o orquestrador depende deles, nunca o
  contrário. Rode `npm run depcruise` antes de abrir o PR se você mexeu
  em imports entre módulos.

## Política de versionamento

[Semantic Versioning 2.0.0](https://semver.org/lang/pt-BR/):

- durante a série `0.x`, **MINOR** pode incluir mudanças incompatíveis e
  **PATCH** preserva compatibilidade;
- a partir de `1.0.0`, **MAJOR** indica quebra na API pública, **MINOR**
  adiciona funcionalidade compatível e **PATCH** contém correções compatíveis.

Apenas a MAJOR mais recente recebe correções de segurança
(ver [SECURITY.md](SECURITY.md)).

## Política de segurança

Vulnerabilidades **não** devem ser reportadas como issues públicas. Veja
[SECURITY.md](SECURITY.md) para o canal apropriado.

## Dúvidas

Abra uma issue ou uma Discussion no repositório do projeto.
