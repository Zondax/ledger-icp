import {LedgerError} from "./common";

export interface ResponseBase {
  errorMessage?: string;
  returnCode: LedgerError;
}

export interface ResponseAddress extends ResponseBase {
  publicKey: Buffer;
  principal: Buffer;
  address: Buffer;
  principalText: string;
}

export interface ResponseVersion extends ResponseBase {
  testMode: boolean;
  major: number;
  minor: number;
  patch: number;
  deviceLocked: boolean;
  targetId: string;
}

export interface ResponseAppInfo extends ResponseBase {
  appName: string;
  appVersion: string;
  flagLen: number;
  flagsValue: number;
  flagRecovery: boolean;
  flagSignedMcuCode: boolean;
  flagOnboarded: boolean;
  flagPINValidated: boolean;
}

export interface ResponseDeviceInfo extends ResponseBase {
  targetId: string;
  seVersion: string;
  flag: string;
  mcuVersion: string;
}

export interface ResponseSign extends ResponseBase {
  preSignHash: Buffer,
  signatureRS: Buffer,
  signatureDER: Buffer,
}
