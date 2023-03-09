import { INSGeneric, ResponseBase } from "@zondax/ledger-js";

export interface ICPIns extends INSGeneric {
  GET_VERSION: 0x00;
  GET_ADDR_SECP256K1: 0x01;
  SIGN_SECP256K1: 0x02;
  SIGN_COMBINED: 0x03;
}

export interface ResponseAddress extends ResponseBase {
  publicKey?: Buffer;
  principal?: Buffer;
  address?: Buffer;
  principalText?: string;
}

export interface ResponseSign extends ResponseBase {
  preSignHash?: Buffer;
  signatureRS?: Buffer;
  signatureDER?: Buffer;
}

export interface ResponseSignUpdateCall extends ResponseBase {
  RequestHash?: Buffer;
  RequestSignatureRS?: Buffer;
  StatusReadHash?: Buffer;
  StatusReadSignatureRS?: Buffer;
}
