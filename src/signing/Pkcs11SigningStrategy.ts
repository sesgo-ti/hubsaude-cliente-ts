/*
 * SPDX-License-Identifier: Apache-2.0
 * Copyright 2025-2026 Estado de Goiás (SES-GO) e Universidade Federal de Goiás (UFG).
 */

import { createHash } from "node:crypto";
import type { Attribute } from "pkcs11js";
import { SigningError } from "../errors/SigningError.js";
import { SmartTokenError } from "../errors/SmartTokenError.js";
import type { CloseableSigningStrategy } from "./SigningStrategy.js";

/**
 * Opções de {@link fromPkcs11}.
 *
 * @property library - caminho do módulo PKCS#11 do fabricante do
 *   HSM/token (`.so` no Linux, `.dll` no Windows) — ex.:
 *   `/usr/lib/softhsm/libsofthsm2.so`
 * @property pin - PIN de acesso ao token. Precisa ser `string`, não
 *   `Buffer`: a API nativa do PKCS#11 (`C_Login`) só aceita `string` —
 *   mesma limitação de plataforma já documentada para
 *   `clientPfxPassphrase`
 * @property keyLabel - `CKA_LABEL` da chave privada a usar. Ao menos um
 *   entre `keyLabel`/`keyId` é obrigatório; informar os dois busca a
 *   chave que combine com ambos
 * @property keyId - `CKA_ID` da chave privada a usar — muitos
 *   HSMs/smart cards pareiam chave privada e certificado por esse
 *   identificador binário compartilhado em vez de (ou além do label),
 *   e alguns fabricantes não preenchem o label de forma consistente
 * @property slot - índice do slot a usar (posição em
 *   `C_GetSlotList`). Mutuamente exclusivo com `tokenLabel`; se nenhum
 *   dos dois for informado, usa o primeiro slot com token presente
 * @property tokenLabel - label do token a localizar entre os slots
 *   disponíveis. Mutuamente exclusivo com `slot`
 * @property jwtAlgorithm - algoritmo JWT que a chave vai assinar
 *   (padrão `"RS384"`) — determina o mecanismo PKCS#11 usado
 */
export interface Pkcs11Options {
  library: string;
  pin: string;
  keyLabel?: string;
  keyId?: Buffer;
  slot?: number;
  tokenLabel?: string;
  jwtAlgorithm?: string;
}

/** Comprimento do salt PSS (bytes), igual ao digest, para cada mecanismo PS*. */
const PSS_SALT_LEN_256 = 32;
const PSS_SALT_LEN_384 = 48;
const PSS_SALT_LEN_512 = 64;

/**
 * Buffer de saída para `C_Sign`, generoso o bastante para qualquer
 * assinatura RSA (até 8192 bits = 1024 bytes) ou EC (até P-521 = 132
 * bytes) suportada por este módulo. `pkcs11js` corta o resultado para o
 * tamanho real devolvido pelo módulo PKCS#11 (ver `modifyMethod` no
 * código-fonte de `pkcs11js`), então superalocar aqui é seguro. Um
 * token com chave RSA maior que 8192 bits (extremamente incomum) ainda
 * falharia por buffer insuficiente — `fromPkcs11` não valida o tamanho
 * da chave antecipadamente, já que handles PKCS#11 são opacos.
 */
const SIGNATURE_BUFFER_SIZE = 1024;

/**
 * Módulo `pkcs11js` carregado dinamicamente — nunca importado
 * estaticamente neste arquivo. Ver {@link loadPkcs11Module} para o
 * motivo.
 */
type Pkcs11Module = typeof import("pkcs11js");

/** Instância de `pkcs11js.PKCS11` — onde vivem os métodos `C_*`. */
type Pkcs11Instance = InstanceType<Pkcs11Module["PKCS11"]>;

/**
 * Carrega o pacote `pkcs11js` sob demanda.
 *
 * `pkcs11js` é uma `peerDependency` **opcional** desta lib (ver
 * `package.json`), não uma dependência normal — instalar um binário
 * nativo que exige compilação (`node-gyp`) em toda instalação da lib,
 * mesmo para quem nunca usa HSM, seria um custo real e desnecessário.
 * Por isso o `import()` aqui é dinâmico, executado só quando
 * {@link fromPkcs11} é chamada — nenhum outro arquivo desta lib importa
 * `pkcs11js` de forma alguma, então consumidores que nunca chamam esta
 * função nunca acionam a resolução do módulo.
 *
 * @throws {SmartTokenError} se `pkcs11js` não estiver instalado
 */
async function loadPkcs11Module(): Promise<Pkcs11Module> {
  try {
    const mod = (await import("pkcs11js")) as unknown as { default: Pkcs11Module };
    return mod.default;
  } catch (err) {
    if ((err as NodeJS.ErrnoException).code === "ERR_MODULE_NOT_FOUND") {
      throw new SmartTokenError("pkcs11js não está instalado. Para usar HSM/PKCS#11, rode: npm install pkcs11js", err);
    }
    throw err;
  }
}

interface Pkcs11Mechanism {
  mechanism: number;
  parameter?: { type: number; hashAlg: number; mgf: number; saltLen: number };
  /**
   * Quando presente, o hash é calculado neste processo (via
   * `node:crypto`) antes de `C_Sign` — o mecanismo é o `CKM_ECDSA` puro,
   * que espera um digest já pronto como entrada, não os dados brutos.
   * Ausente para os mecanismos RSA (combinam hash e assinatura num único
   * passo no próprio token).
   */
  digestAlgorithm?: "sha256" | "sha384" | "sha512";
}

/**
 * Converte um algoritmo JWT (JWA) para o mecanismo PKCS#11
 * correspondente.
 *
 * Os mecanismos RSA combinam hash e assinatura num único passo (ex.:
 * `CKM_SHA384_RSA_PKCS`) — o token calcula o hash internamente. Já os
 * mecanismos ECDSA usam o `CKM_ECDSA` **puro** (sem hash embutido): o
 * hash é calculado aqui mesmo, em `node:crypto`, antes de chamar
 * `C_Sign` — ver `digestAlgorithm` em {@link Pkcs11Mechanism}. Motivo:
 * nem todo HSM/token oferece as variantes combinadas de ECDSA
 * (`CKM_ECDSA_SHA256`/`384`/`512`); `CKM_ECDSA` puro é o mínimo
 * denominador comum entre implementações PKCS#11 de fabricantes
 * variados.
 *
 * O formato de saída do PKCS#11 para ECDSA independe de onde o hash é
 * calculado: `CKM_ECDSA` puro (recebendo o digest já calculado) devolve
 * a assinatura no mesmo formato bruto `R||S` (96 bytes para P-384) que
 * as variantes combinadas.
 *
 * @throws {SmartTokenError} se o algoritmo não for reconhecido
 */
function jwtAlgorithmToPkcs11(pkcs11: Pkcs11Module, jwtAlgorithm: string): Pkcs11Mechanism {
  const rsaPss = (hashAlg: number, mgf: number, saltLen: number) => ({
    type: pkcs11.CK_PARAMS_RSA_PSS,
    hashAlg,
    mgf,
    saltLen,
  });
  switch (jwtAlgorithm.toUpperCase()) {
    case "RS256":
      return { mechanism: pkcs11.CKM_SHA256_RSA_PKCS };
    case "RS384":
      return { mechanism: pkcs11.CKM_SHA384_RSA_PKCS };
    case "RS512":
      return { mechanism: pkcs11.CKM_SHA512_RSA_PKCS };
    case "PS256":
      return {
        mechanism: pkcs11.CKM_SHA256_RSA_PKCS_PSS,
        parameter: rsaPss(pkcs11.CKM_SHA256, pkcs11.CKG_MGF1_SHA256, PSS_SALT_LEN_256),
      };
    case "PS384":
      return {
        mechanism: pkcs11.CKM_SHA384_RSA_PKCS_PSS,
        parameter: rsaPss(pkcs11.CKM_SHA384, pkcs11.CKG_MGF1_SHA384, PSS_SALT_LEN_384),
      };
    case "PS512":
      return {
        mechanism: pkcs11.CKM_SHA512_RSA_PKCS_PSS,
        parameter: rsaPss(pkcs11.CKM_SHA512, pkcs11.CKG_MGF1_SHA512, PSS_SALT_LEN_512),
      };
    case "ES256":
      return { mechanism: pkcs11.CKM_ECDSA, digestAlgorithm: "sha256" };
    case "ES384":
      return { mechanism: pkcs11.CKM_ECDSA, digestAlgorithm: "sha384" };
    case "ES512":
      return { mechanism: pkcs11.CKM_ECDSA, digestAlgorithm: "sha512" };
    default:
      throw new SmartTokenError(
        `Algoritmo JWT não suportado para PKCS#11: ${jwtAlgorithm}. Algoritmos válidos: ` +
          "RS256, RS384, RS512, PS256, PS384, PS512, ES256, ES384, ES512",
      );
  }
}

function findSlot(pkcs11: Pkcs11Module, p11: Pkcs11Instance, options: Pkcs11Options): Buffer {
  if (options.slot !== undefined && options.tokenLabel !== undefined) {
    throw new Error("Defina slot OU tokenLabel para localizar o token PKCS#11, não ambos");
  }

  const slots = p11.C_GetSlotList(true);
  if (slots.length === 0) {
    throw new SmartTokenError(`Nenhum slot com token presente encontrado em ${options.library}`);
  }

  if (options.slot !== undefined) {
    const slot = slots[options.slot];
    if (slot === undefined) {
      throw new SmartTokenError(`Slot ${options.slot} não existe (${slots.length} slot(s) com token disponível)`);
    }
    return slot;
  }

  if (options.tokenLabel !== undefined) {
    for (const slot of slots) {
      const info = p11.C_GetTokenInfo(slot);
      if (info.label.trim() === options.tokenLabel) {
        return slot;
      }
    }
    throw new SmartTokenError(`Nenhum token com label '${options.tokenLabel}' encontrado`);
  }

  const firstSlot = slots[0];
  if (firstSlot === undefined) {
    throw new SmartTokenError(`Nenhum slot com token presente encontrado em ${options.library}`);
  }
  return firstSlot;
}

function findPrivateKey(
  pkcs11: Pkcs11Module,
  p11: Pkcs11Instance,
  session: Buffer,
  options: Pick<Pkcs11Options, "keyLabel" | "keyId">,
): Buffer {
  if (options.keyLabel === undefined && options.keyId === undefined) {
    throw new Error("Defina keyLabel e/ou keyId para localizar a chave privada PKCS#11");
  }

  const template: Attribute[] = [{ type: pkcs11.CKA_CLASS, value: pkcs11.CKO_PRIVATE_KEY }];
  if (options.keyLabel !== undefined) {
    template.push({ type: pkcs11.CKA_LABEL, value: options.keyLabel });
  }
  if (options.keyId !== undefined) {
    template.push({ type: pkcs11.CKA_ID, value: options.keyId });
  }

  const description = [
    options.keyLabel !== undefined ? `label '${options.keyLabel}'` : undefined,
    options.keyId !== undefined ? `id '${options.keyId.toString("hex")}'` : undefined,
  ]
    .filter((part) => part !== undefined)
    .join(" e ");

  p11.C_FindObjectsInit(session, template);
  try {
    const key = p11.C_FindObjects(session);
    if (key === null) {
      throw new SmartTokenError(`Nenhuma chave privada com ${description} encontrada no token`);
    }
    return key;
  } finally {
    p11.C_FindObjectsFinal(session);
  }
}

/**
 * Chama `C_Initialize`, tolerando `CKR_CRYPTOKI_ALREADY_INITIALIZED`.
 *
 * O módulo nativo PKCS#11 (o `.so`/`.dll` em si) é um singleton por
 * processo — carregado uma única vez via `dlopen`, mesmo que várias
 * instâncias de `pkcs11js.PKCS11` o carreguem separadamente. Chamar
 * `fromPkcs11` mais de uma vez no mesmo processo
 * (cenário real — mais de um cliente usando HSM, ou só a própria suíte
 * de testes) faz a segunda chamada de `C_Initialize` falhar com
 * `CKR_CRYPTOKI_ALREADY_INITIALIZED`, mesmo o módulo estando
 * perfeitamente utilizável nesse estado — não é um erro real, é o
 * comportamento esperado do PKCS#11 para reinicialização.
 *
 * @throws {SmartTokenError} para qualquer outra falha de inicialização
 */
function initializeOnce(pkcs11: Pkcs11Module, p11: Pkcs11Instance, library: string): void {
  try {
    p11.C_Initialize();
  } catch (err) {
    const code = (err as { code?: number }).code;
    if (code === pkcs11.CKR_CRYPTOKI_ALREADY_INITIALIZED) {
      return;
    }
    throw new SmartTokenError(`Falha ao inicializar o módulo PKCS#11: ${library}`, err);
  }
}

/**
 * Cria uma {@link SigningStrategy} que assina usando uma chave privada
 * mantida num HSM/token via PKCS#11 — a chave nunca sai do hardware; a
 * assinatura é delegada ao dispositivo (RF-12.2).
 *
 * O Node não tem suporte nativo a PKCS#11; esta função usa `pkcs11js`,
 * carregado sob demanda (ver {@link loadPkcs11Module}) — instale-o
 * separadamente (`npm install pkcs11js`) apenas se for usar esta
 * função.
 *
 * A sessão com o token é aberta e autenticada uma única vez, nesta
 * chamada (fail-fast: PIN incorreto ou chave inexistente falham aqui,
 * não na primeira assinatura — RF-12.3; se algo falhar depois de abrir
 * a sessão, ela é fechada antes do erro se propagar, evitando vazar o
 * handle) e mantida aberta para todas as assinaturas subsequentes
 * feitas pela `SigningStrategy` devolvida. `createSmartTokenClient`
 * invoca `close()` automaticamente ao fechar o cliente (ver
 * {@link CloseableSigningStrategy}) — fecha só esta sessão específica,
 * sem afetar outras. `close()` não faz logout nem chama `C_Finalize` no
 * módulo (ver o comentário em `strategy.close` abaixo para o motivo).
 *
 * @param options - configuração de acesso ao HSM/token
 * @returns uma {@link CloseableSigningStrategy} assíncrona pronta para uso
 * @throws {SmartTokenError} se `pkcs11js` não estiver instalado, o
 *   módulo/slot/token/chave não forem encontrados, ou o PIN for inválido
 * @throws {Error} se nem `keyLabel` nem `keyId` forem informados
 * @throws {SigningError} se uma operação de assinatura específica falhar
 */
export async function fromPkcs11(options: Pkcs11Options): Promise<CloseableSigningStrategy> {
  const pkcs11 = await loadPkcs11Module();
  const jwtAlgorithm = options.jwtAlgorithm ?? "RS384";
  const { mechanism, parameter, digestAlgorithm } = jwtAlgorithmToPkcs11(pkcs11, jwtAlgorithm);

  const p11: Pkcs11Instance = new pkcs11.PKCS11();
  try {
    p11.load(options.library);
  } catch (err) {
    throw new SmartTokenError(`Falha ao carregar o módulo PKCS#11: ${options.library}`, err);
  }
  initializeOnce(pkcs11, p11, options.library);

  const slot = findSlot(pkcs11, p11, options);
  const session = p11.C_OpenSession(slot, pkcs11.CKF_SERIAL_SESSION);
  let privateKey: Buffer;
  try {
    try {
      p11.C_Login(session, pkcs11.CKU_USER, options.pin);
    } catch (err) {
      const code = (err as { code?: number }).code;
      // O login é uma propriedade do token, não da sessão, na maioria
      // das implementações PKCS#11: uma segunda sessão no mesmo token —
      // outra chamada a fromPkcs11 no mesmo processo — encontra o token
      // já autenticado. Não é uma falha real, então não a tratamos como
      // PIN incorreto.
      if (code !== pkcs11.CKR_USER_ALREADY_LOGGED_IN) {
        throw new SmartTokenError(`Falha ao autenticar no token PKCS#11 (PIN incorreto?): ${options.library}`, err);
      }
    }

    privateKey = findPrivateKey(pkcs11, p11, session, options);
  } catch (err) {
    // Sessão aberta mas algo depois falhou (login ou busca da chave) —
    // fecha antes de propagar, para não vazar o handle. Tokens têm um
    // limite de sessões simultâneas; sem isso, cada fromPkcs11 que
    // falhasse (ex.: keyLabel errado) deixaria uma sessão presa.
    try {
      p11.C_CloseSession(session);
    } catch {
      // ignorado — já estamos propagando o erro original
    }
    throw err;
  }

  const strategy: CloseableSigningStrategy = (data: Uint8Array): Promise<Uint8Array> => {
    return new Promise((resolve, reject) => {
      // ECDSA usa o mecanismo puro (`digestAlgorithm` presente): o hash
      // é calculado aqui, não pelo token — ver jwtAlgorithmToPkcs11.
      const dataToSign = digestAlgorithm ? createHash(digestAlgorithm).update(data).digest() : Buffer.from(data);
      try {
        p11.C_SignInit(session, { mechanism, parameter }, privateKey);
      } catch (err) {
        reject(new SigningError(`Falha ao assinar dados via PKCS#11 (mecanismo ${jwtAlgorithm})`, err));
        return;
      }
      // Callback assíncrono, não a variante síncrona: assinar num HSM
      // real pode envolver round-trip de I/O real (USB, rede) — ao
      // contrário de `crypto.sign` em memória (CPU-only, rápido), não
      // deveria bloquear o event loop do Node.
      p11.C_Sign(session, dataToSign, Buffer.alloc(SIGNATURE_BUFFER_SIZE), (err, signature) => {
        if (err) {
          reject(new SigningError(`Falha ao assinar dados via PKCS#11 (mecanismo ${jwtAlgorithm})`, err));
          return;
        }
        resolve(signature);
      });
    });
  };

  strategy.close = (): void => {
    // Fecha só esta sessão — não faz C_Logout. Login é uma propriedade
    // do token, não da sessão, na maioria das implementações: outra
    // chamada a fromPkcs11 para o mesmo token pode ter uma sessão
    // própria ainda em uso, e um logout aqui a derrubaria também.
    // Fechar a sessão (sem logout) já é suficiente para invalidar as
    // operações desta estratégia especificamente. Também tolera
    // fechamento duplicado — close() deve ser best-effort/idempotente,
    // nunca lançar e impedir o restante do encerramento do cliente.
    try {
      p11.C_CloseSession(session);
    } catch {
      // ignorado de propósito — ver comentário acima
    }
  };

  return strategy;
}
