/** @type {import('dependency-cruiser').IConfiguration} */
export default {
  forbidden: [
    {
      name: "no-circular",
      severity: "error",
      comment: "Nenhum módulo deve depender, direta ou indiretamente, de si mesmo.",
      from: {},
      to: { circular: true },
    },
    {
      name: "no-leaf-to-client",
      severity: "error",
      comment:
        "Módulos de apoio (errors, signing, tls, resilience, token, trace, logging) não devem " +
        "depender de client/ — client/ é o orquestrador que depende deles, nunca o contrário.",
      from: { path: "^src/(errors|signing|tls|resilience|token|trace|logging)/" },
      to: { path: "^src/client/" },
    },
  ],
  options: {
    doNotFollow: { path: "node_modules" },
    tsPreCompilationDeps: true,
    tsConfig: {
      fileName: "tsconfig.json",
    },
    enhancedResolveOptions: {
      exportsFields: ["exports"],
      conditionNames: ["import", "require", "node", "default"],
    },
    reporterOptions: {
      dot: {
        collapsePattern: "node_modules/[^/]+",
      },
    },
  },
};
