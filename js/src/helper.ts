import { errorCodeToString } from "@zondax/ledger-js";
import { ADDRLEN, PKLEN, PRINCIPAL_LEN } from "./consts";
import { ResponseAddress } from "./types";

export function processGetAddrResponse(response: Buffer): ResponseAddress {
  const errorCodeData = response.subarray(-2);
  const returnCode = errorCodeData[0] * 256 + errorCodeData[1];

  const publicKey = Buffer.from(response.subarray(0, PKLEN));
  response = response.subarray(PKLEN);

  const principal = Buffer.from(response.subarray(0, PRINCIPAL_LEN));
  response = response.subarray(PRINCIPAL_LEN);

  const address = Buffer.from(response.subarray(0, ADDRLEN));
  response = response.subarray(ADDRLEN);

  const principalText = Buffer.from(response.subarray(0, -2))
    .toString()
    .replace(/(.{5})/g, "$1-");
  return {
    publicKey,
    principal,
    address,
    principalText,
    returnCode,
    errorMessage: errorCodeToString(returnCode),
  };
}
