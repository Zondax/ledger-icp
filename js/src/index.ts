/** ******************************************************************************
 *  (c) 2019-2020 Zondax GmbH
 *  (c) 2016-2017 Ledger
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 ******************************************************************************* */
import { PREHASH_LEN, SIGRSLEN } from "./consts";
import {
  type ICPIns,
  type TokenInfo,
  type ResponseAddress,
  type ResponseSign,
  type ResponseSignUpdateCall,
  type ResponseTokenRegistry,
  type ResponseTokenRegistrySize,
} from "./types";

import GenericApp, {
  type ConstructorParams,
  errorCodeToString,
  LedgerError,
  PAYLOAD_TYPE,
  processErrorResponse,
  type Transport,
} from "@zondax/ledger-js";
import { processGetAddrResponse, processTokenRegistrySizeResponse, processTokenInfoResponse } from "./helper";

export * from "./types";
export { SIGN_VALUES_P2 } from "./consts";

export default class InternetComputerApp extends GenericApp {
  readonly INS!: ICPIns;
  constructor(transport: Transport) {
    if (transport == null) throw new Error("Transport has not been defined");

    const params: ConstructorParams = {
      cla: 0x11,
      ins: {
        GET_VERSION: 0x00,
        GET_ADDR_SECP256K1: 0x01,
        SIGN_SECP256K1: 0x02,
        SIGN_COMBINED: 0x03,
        SAVE_CONSENT: 0x04,
        SAVE_CANISTER_CALL: 0x05,
        SAVE_CERITIFACE_AND_VERIFY: 0x06,
        GET_REGISTRY_LEN: 0x07,
        GET_TOKEN_I: 0x08,
      },
      p1Values: {
        ONLY_RETRIEVE: 0x00,
        SHOW_ADDRESS_IN_DEVICE: 0x01,
      },
      acceptedPathLengths: [5],
      chunkSize: 250,
    };
    super(transport, params);
  }

  async getAddressAndPubKey(path: string): Promise<ResponseAddress> {
    const serializedPath = this.serializePath(path);
    return await this.transport
      .send(this.CLA, this.INS.GET_ADDR_SECP256K1, this.P1_VALUES.ONLY_RETRIEVE, 0, serializedPath, [0x9000])
      .then(processGetAddrResponse, processErrorResponse);
  }

  async showAddressAndPubKey(path: string): Promise<ResponseAddress> {
    const serializedPath = this.serializePath(path);

    return await this.transport
      .send(this.CLA, this.INS.GET_ADDR_SECP256K1, this.P1_VALUES.SHOW_ADDRESS_IN_DEVICE, 0, serializedPath, [
        LedgerError.NoErrors,
      ])
      .then(processGetAddrResponse, processErrorResponse);
  }

  async signSendChunk(
    chunkIdx: number,
    chunkNum: number,
    chunk: Buffer,
    txtype: number,
    ins: number,
  ): Promise<ResponseSign> {
    let payloadType = PAYLOAD_TYPE.ADD;
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT;
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST;
    }

    return await this.transport
      .send(this.CLA, ins, payloadType, txtype, chunk, [
        LedgerError.NoErrors,
        LedgerError.DataIsInvalid,
        LedgerError.BadKeyHandle,
        LedgerError.SignVerifyError,
      ])
      .then((response: Buffer) => {
        const errorCodeData = response.subarray(-2);
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
        let errorMessage = errorCodeToString(returnCode);

        let preSignHash = Buffer.alloc(0);
        let signatureRS = Buffer.alloc(0);
        let signatureDER = Buffer.alloc(0);

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid ||
          returnCode === LedgerError.SignVerifyError
        ) {
          errorMessage = `${errorMessage} : ${response.subarray(0, response.length - 2).toString("ascii")}`;
        }

        if (returnCode === LedgerError.NoErrors && response.length > 2) {
          preSignHash = response.subarray(0, PREHASH_LEN);
          signatureRS = response.subarray(PREHASH_LEN, PREHASH_LEN + SIGRSLEN);
          signatureDER = response.subarray(PREHASH_LEN + SIGRSLEN + 1, response.length - 2);
          return {
            preSignHash,
            signatureRS,
            signatureDER,
            returnCode,
            errorMessage,
          };
        }

        return {
          returnCode,
          errorMessage,
        };
      }, processErrorResponse);
  }

  async sign(path: string, message: Buffer, txtype: number): Promise<ResponseSign> {
    const chunks = this.prepareChunks(path, message);
    return await this.signSendChunk(1, chunks.length, chunks[0], txtype % 256, this.INS.SIGN_SECP256K1).then(
      async (response) => {
        let result: ResponseSign = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
        };

        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], txtype % 256, this.INS.SIGN_SECP256K1);
          if (result.returnCode !== LedgerError.NoErrors) {
            break;
          }
        }
        return result;
      },
      processErrorResponse,
    );
  }

  async signSendChunkUpdateCall(
    chunkIdx: number,
    chunkNum: number,
    chunk: Buffer,
    txtype: number,
  ): Promise<ResponseSignUpdateCall> {
    let payloadType = PAYLOAD_TYPE.ADD;
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT;
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST;
    }

    return await this.transport
      .send(this.CLA, this.INS.SIGN_COMBINED, payloadType, txtype, chunk, [
        LedgerError.NoErrors,
        LedgerError.DataIsInvalid,
        LedgerError.BadKeyHandle,
        LedgerError.SignVerifyError,
      ])
      .then((response: Buffer) => {
        const errorCodeData = response.subarray(-2);
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
        let errorMessage = errorCodeToString(returnCode);

        let RequestHash = Buffer.alloc(0);
        let RequestSignatureRS = Buffer.alloc(0);
        let StatusReadHash = Buffer.alloc(0);
        let StatusReadSignatureRS = Buffer.alloc(0);

        if (
          returnCode === LedgerError.BadKeyHandle ||
          returnCode === LedgerError.DataIsInvalid ||
          returnCode === LedgerError.SignVerifyError
        ) {
          errorMessage = `${errorMessage} : ${response.subarray(0, response.length - 2).toString("ascii")}`;
        }

        if (returnCode === LedgerError.NoErrors && response.length > 2) {
          RequestHash = response.subarray(0, 32);
          RequestSignatureRS = response.subarray(32, 96);
          StatusReadHash = response.subarray(96, 128);
          StatusReadSignatureRS = response.subarray(128, 192);
          return {
            RequestHash,
            RequestSignatureRS,
            StatusReadHash,
            StatusReadSignatureRS,
            returnCode,
            errorMessage,
          };
        }

        return {
          returnCode,
          errorMessage,
        };
      }, processErrorResponse);
  }

  async signUpdateCall(
    path: string,
    request: Buffer,
    checkStatus: Buffer,
    txtype: number,
  ): Promise<ResponseSignUpdateCall> {
    const message = Buffer.alloc(8 + request.byteLength + checkStatus.byteLength);
    message.writeUInt32LE(checkStatus.byteLength, 0);
    checkStatus.copy(message, 4);
    message.writeUInt32LE(request.byteLength, 4 + checkStatus.byteLength);
    request.copy(message, 8 + checkStatus.byteLength);
    console.log(message.toString("hex"));
    const chunks = this.prepareChunks(path, message);
    return await this.signSendChunk(1, chunks.length, chunks[0], txtype % 256, this.INS.SIGN_SECP256K1).then(
      async (response) => {
        let result: ResponseSignUpdateCall = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
        };

        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunkUpdateCall(1 + i, chunks.length, chunks[i], txtype % 256);
          if (result.returnCode !== LedgerError.NoErrors) {
            break;
          }
        }
        return result;
      },
      processErrorResponse,
    );
  }

  async sendChunk(chunkIdx: number, chunkNum: number, chunk: Buffer, ins: number) {
    let payloadType = PAYLOAD_TYPE.ADD;
    const p2 = 0;
    if (chunkIdx === 1) {
      payloadType = PAYLOAD_TYPE.INIT;
    }
    if (chunkIdx === chunkNum) {
      payloadType = PAYLOAD_TYPE.LAST;
    }

    return await this.transport
      .send(this.CLA, ins, payloadType, p2, chunk, [
        LedgerError.NoErrors,
        LedgerError.DataIsInvalid,
        LedgerError.BadKeyHandle,
        LedgerError.SignVerifyError,
      ])
      .then((response: Buffer) => {
        const errorCodeData = response.subarray(-2);
        const returnCode = errorCodeData[0] * 256 + errorCodeData[1];
        let errorMessage = errorCodeToString(returnCode);

        return {
          returnCode,
          errorMessage,
        };
      }, processErrorResponse);
  }

  async sendData(path: string, data: string, instruction: number): Promise<ResponseSign> {
    const data_buf = Buffer.from(data, "hex");
    const chunks = this.prepareChunks(path, data_buf);
    return await this.sendChunk(1, chunks.length, chunks[0], instruction).then(async (response) => {
      let result = {
        returnCode: response.returnCode,
        errorMessage: response.errorMessage,
      };
      for (let i = 1; i < chunks.length; i += 1) {
        // eslint-disable-next-line no-await-in-loop
        result = await this.sendChunk(1 + i, chunks.length, chunks[i], instruction);
        if (result.returnCode !== LedgerError.NoErrors) {
          break;
        }
      }
      return result;
    }, processErrorResponse);
  }

  async sendCertificateAndSig(path: string, data: string): Promise<ResponseSign> {
    const chunks = this.prepareChunks(path, Buffer.from(data, "hex"));
    return await this.signSendChunk(1, chunks.length, chunks[0], 0, this.INS.SAVE_CERITIFACE_AND_VERIFY).then(
      async (response) => {
        let result = {
          returnCode: response.returnCode,
          errorMessage: response.errorMessage,
        };
        for (let i = 1; i < chunks.length; i += 1) {
          // eslint-disable-next-line no-await-in-loop
          result = await this.signSendChunk(1 + i, chunks.length, chunks[i], 0, this.INS.SAVE_CERITIFACE_AND_VERIFY);
          if (result.returnCode !== LedgerError.NoErrors) {
            break;
          }
        }
        return result;
      },
      processErrorResponse,
    );
  }

  async signBls(
    path: string,
    consent_request: string,
    canister_call: string,
    certificate: string,
  ): Promise<ResponseSign> {
    // Check if all strings are not empty
    if (!consent_request || !canister_call || !certificate) {
      throw new Error("All parameters must be non-empty strings");
    }
    let result: ResponseSign;

    // Send consent_request
    result = await this.sendData(path, consent_request, this.INS.SAVE_CONSENT);
    if (result.returnCode !== LedgerError.NoErrors) return result;

    // Send canister_call
    result = await this.sendData(path, canister_call, this.INS.SAVE_CANISTER_CALL);
    if (result.returnCode !== LedgerError.NoErrors) return result;

    // Send certificate and sign
    return await this.sendCertificateAndSig(path, certificate);
  }

  async _getTokenRegistrySize(): Promise<ResponseTokenRegistrySize> {
    return await this.transport
      .send(this.CLA, this.INS.GET_REGISTRY_LEN, 0, 0)
      .then(processTokenRegistrySizeResponse, processErrorResponse);
  }

  async tokenRegistry(): Promise<ResponseTokenRegistry> {
    const registrySize = await this._getTokenRegistrySize();
    if (registrySize.returnCode !== LedgerError.NoErrors || registrySize.RegistrySize === undefined) {
      return {
        returnCode: registrySize.returnCode,
        errorMessage: registrySize.errorMessage,
      };
    }

    let tokenRegistry: TokenInfo[] = [];

    for (let i = 0; i < registrySize.RegistrySize; i += 1) {
      const response = await this.transport.send(this.CLA, this.INS.GET_TOKEN_I, i, 0).then(
        (response: Buffer) => processTokenInfoResponse(response),
        (error: any) => processErrorResponse(error),
      );

      // Type guard to check if response is ResponseTokenInfo
      if (!response || "tokenInfo" in response === false || response.returnCode !== LedgerError.NoErrors) {
        return {
          returnCode: response?.returnCode || LedgerError.ExecutionError,
          errorMessage: response?.errorMessage || "Failed to get token info",
        };
      }

      // At this point TypeScript knows response has tokenInfo
      if (response.tokenInfo) {
        tokenRegistry.push(response.tokenInfo);
      }
    }

    return {
      returnCode: LedgerError.NoErrors,
      errorMessage: "No errors",
      tokenRegistry: tokenRegistry,
    };
  }
}
