/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

/**
 * Estratégia de assinatura digital que abstrai o mecanismo criptográfico.
 *
 * Permite desacoplar a operação de assinatura da fonte do material
 * criptográfico. Implementações possíveis:
 *
 * - Chave em memória (carregada de um arquivo PEM);
 * - HSM/Smart Token via PKCS#11 (a chave nunca sai do hardware);
 * - Serviço remoto de assinatura (ex.: HashiCorp Vault Transit, OpenBao).
 *
 * O retorno pode ser síncrono (`Uint8Array`) ou assíncrono (`Promise`),
 * permitindo tanto chaves locais quanto assinadores remotos.
 *
 * @param data - bytes a serem assinados (o `header.payload` do JWT,
 *   já codificados em Base64URL e concatenados)
 * @returns a assinatura digital em formato bruto (não Base64), ou uma
 *   promessa que resolve para ela
 */
export type SigningStrategy = (data: Uint8Array) => Uint8Array | Promise<Uint8Array>;

/**
 * Convenção opcional: uma {@link SigningStrategy} que mantém um recurso
 * externo (ex.: uma sessão PKCS#11 aberta) pode anexar um método `close`
 * a si mesma — funções são objetos em JS/TS, então isso não exige mudar
 * o tipo `SigningStrategy` nem quebra estratégias existentes.
 * `SmartTokenClient.close()` invoca `close()` automaticamente, se
 * presente, ao encerrar o cliente.
 *
 * Só {@link fromPkcs11} usa isso hoje — estratégias de chave em memória
 * (`fromPrivateKey`, `fromPkcs12`) não mantêm recurso nenhum para
 * liberar.
 */
export type CloseableSigningStrategy = SigningStrategy & {
  close?: () => void | Promise<void>;
};
