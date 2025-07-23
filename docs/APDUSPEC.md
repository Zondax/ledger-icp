# Internet Computer App

## General structure

The general structure of commands and responses is as follows:

#### Commands

| Field   | Type     | Content                | Note |
| :------ | :------- | :--------------------- | ---- |
| CLA     | byte (1) | Application Identifier | 0x11 |
| INS     | byte (1) | Instruction ID         |      |
| P1      | byte (1) | Parameter 1            |      |
| P2      | byte (1) | Parameter 2            |      |
| L       | byte (1) | Bytes in payload       |      |
| PAYLOAD | byte (L) | Payload                |      |

#### Response

| Field   | Type     | Content     | Note                     |
| ------- | -------- | ----------- | ------------------------ |
| ANSWER  | byte (?) | Answer      | depends on the command   |
| SW1-SW2 | byte (2) | Return code | see list of return codes |

#### Return codes

| Return code | Description              |
| ----------- | ------------------------ |
| 0x6400      | Execution Error          |
| 0x6700      | Wrong buffer length      |
| 0x6982      | Empty buffer             |
| 0x6983      | Output buffer too small  |
| 0x6984      | Data is invalid          |
| 0x6985      | Conditions not satisfied |
| 0x6986      | Command not allowed      |
| 0x6987      | Tx is not initialized    |
| 0x6A80      | Bad key handle           |
| 0x6B00      | P1/P2 are invalid        |
| 0x6D00      | INS not supported        |
| 0x6E00      | CLA not supported        |
| 0x6F00      | Unknown                  |
| 0x6F01      | Sign / verify error      |
| 0x9000      | Success                  |
| 0x9001      | Busy                     |

---------

## Command definition

### GET_VERSION

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0x11     |
| INS   | byte (1) | Instruction ID         | 0x00     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field   | Type     | Content          | Note                            |
| ------- | -------- | ---------------- | ------------------------------- |
| TEST    | byte (1) | Test Mode        | 0xFF means test mode is enabled |
| MAJOR   | byte (1) | Version Major    |                                 |
| MINOR   | byte (1) | Version Minor    |                                 |
| PATCH   | byte (1) | Version Patch    |                                 |
| LOCKED  | byte (1) | Device is locked |                                 |
| SW1-SW2 | byte (2) | Return code      | see list of return codes        |

--------------

### INS_GET_ADDR

#### Command

| Field      | Type           | Content                | Expected          |
| ---------- | -------------- | ---------------------- | ----------------- |
| CLA        | byte (1)       | Application Identifier | 0x11              |
| INS        | byte (1)       | Instruction ID         | 0x01              |
| P1         | byte (1)       | Request User confirmation | No = 0         |
| P2         | byte (1)       | Parameter 2            | ignored           |
| L          | byte (1)       | Bytes in payload       | (depends)         |
| Path[0]    | byte (4)       | Derivation Path Data   | 0x80000000 | 44   |
| Path[1]    | byte (4)       | Derivation Path Data   | 0x80000000 | 461' |
| Path[2]    | byte (4)       | Derivation Path Data   | ?                 |
| Path[3]    | byte (4)       | Derivation Path Data   | ?                 |
| Path[4]    | byte (4)       | Derivation Path Data   | ?                 |

#### Response

| Field   | Type      | Content               | Note                     |
| ------- | --------- | --------------------- | ------------------------ |
| PK      | byte (65) | Public Key            |                          |
| ADDR_B_LEN | byte (1)| ADDR_B Length    | |
| ADDR_B   | byte (??) | Address as Bytes               |  |
| ADDR_S_LEN | byte (1)| ADDR_S Len    ||
| ADDR_S    | byte (??) | Address as String               |  |
| SW1-SW2 | byte (2)  | Return code           | see list of return codes |

### INS_SIGN

#### Command

| Field | Type     | Content                | Expected  |
| ----- | -------- | ---------------------- | --------- |
| CLA   | byte (1) | Application Identifier | 0x11      |
| INS   | byte (1) | Instruction ID         | 0x02      |
| P1    | byte (1) | Payload desc           | 0 = init  |
|       |          |                        | 1 = add   |
|       |          |                        | 2 = last  |
| P2    | byte (1) | ----                   | is_stake_tx  |
| L     | byte (1) | Bytes in payload       | (depends) |

The first packet/chunk includes only the derivation path

If the transaction blob is from a Neuron-stake transaction, it expects P2 == 1.
Otherwise P2 needs to be 0.

All other packets/chunks contain data chunks that are described below

*First Packet*

| Field      | Type     | Content                | Expected  |
| ---------- | -------- | ---------------------- | --------- |
| Path[0]    | byte (4) | Derivation Path Data   | 44        |
| Path[1]    | byte (4) | Derivation Path Data   | 461       |
| Path[2]    | byte (4) | Derivation Path Data   | ?         |
| Path[3]    | byte (4) | Derivation Path Data   | ?         |
| Path[4]    | byte (4) | Derivation Path Data   | ?         |

*Other Chunks/Packets*

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Data    | bytes... | Message         |          |

Data is defined as:

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Message | bytes..  | CBOR data to sign   |      |

#### Response

| Field           | Type            | Content     | Note                     |
| --------------- | --------------- | ----------- | ------------------------ |
| secp256k1 R     | byte (32)       | Signature   |                          |
| secp256k1 S     | byte (32)       | Signature   |                          |
| secp256k1 V     | byte (1)        | Signature   |                          |
| SIG             | byte (variable) | Signature   | DER format               |
| SW1-SW2         | byte (2)        | Return code | see list of return codes |

--------------

### INS_SIGN_COMBINED

#### Command

| Field | Type     | Content                | Expected     |
| ----- | -------- | ---------------------- | ------------ |
| CLA   | byte (1) | Application Identifier | 0x11         |
| INS   | byte (1) | Instruction ID         | 0x03         |
| P1    | byte (1) | Payload desc           | 0 = init     |
|       |          |                        | 1 = add      |
|       |          |                        | 2 = last     |
| P2    | byte (1) | ----                   | is_stake_tx  |
| L     | byte (1) | Bytes in payload       | (depends)    |

The first packet/chunk includes only the derivation path

If the transaction blob is from a Neuron-stake transaction, it expects P2 == 1.
Otherwise P2 needs to be 0.

All other packets/chunks contain data chunks that are described below

*First Packet*

| Field      | Type     | Content                | Expected  |
| ---------- | -------- | ---------------------- | --------- |
| Path[0]    | byte (4) | Derivation Path Data   | 44        |
| Path[1]    | byte (4) | Derivation Path Data   | 461       |
| Path[2]    | byte (4) | Derivation Path Data   | ?         |
| Path[3]    | byte (4) | Derivation Path Data   | ?         |
| Path[4]    | byte (4) | Derivation Path Data   | ?         |

*Other Chunks/Packets*

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Data    | bytes... | Combined Message|          |

Data is defined as:

| Field             | Type     | Content                   | Expected |
| ----------------- | -------- | ------------------------- | -------- |
| State Read Length | byte (4) | Length of state read data |          |
| State Read Data   | bytes..  | State read CBOR data      |          |
| Request Length    | byte (4) | Length of request data    |          |
| Request Data      | bytes..  | Request CBOR data         |          |         

#### Response

| Field                  | Type      | Content                 | Note                     |
| ---------------------- | --------- | ----------------------- | ------------------------ |
| Request Hash           | byte (32) | Hash of request data    |                          |
| Request Signature      | byte (64) | Signature request hash  |                          |
| State Read Hash        | byte (32) | Hash of state read data |                          |
| State Read Signature   | byte (64) | Signature state read    |                          |
| SW1-SW2                | byte (2)  | Return code             | see list of return codes |

--------------

### INS_CONSENT_REQUEST

#### Command

| Field | Type     | Content                | Expected     |
| ----- | -------- | ---------------------- | ------------ |
| CLA   | byte (1) | Application Identifier | 0x11         |
| INS   | byte (1) | Instruction ID         | 0x04         |
| P1    | byte (1) | Payload desc           | 0 = init     |
|       |          |                        | 1 = add      |
|       |          |                        | 2 = last     |
| P2    | byte (1) | ----                   | ignored      |
| L     | byte (1) | Bytes in payload       | (depends)    |

The first packet/chunk includes only the derivation path

*First Packet*

| Field      | Type     | Content                | Expected  |
| ---------- | -------- | ---------------------- | --------- |
| Path[0]    | byte (4) | Derivation Path Data   | 44        |
| Path[1]    | byte (4) | Derivation Path Data   | 461       |
| Path[2]    | byte (4) | Derivation Path Data   | ?         |
| Path[3]    | byte (4) | Derivation Path Data   | ?         |
| Path[4]    | byte (4) | Derivation Path Data   | ?         |

*Other Chunks/Packets*

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Data    | bytes... | Consent Request |          |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

--------------

### INS_CANISTER_CALL_TX

#### Command

| Field   | Type     | Content                | Expected     |
| ------- | -------- | ---------------------- | ------------ |
| CLA     | byte (1) | Application Identifier | 0x11         |
| INS     | byte (1) | Instruction ID         | 0x05         |
| P1      | byte (1) | Payload desc           | 0 = init     |
|         |          |                        | 1 = add      |
|         |          |                        | 2 = last     |
| P2      | byte (1) | ----                   | ignored      |
| L       | byte (1) | Bytes in payload       | (depends)    |

The first packet/chunk includes only the derivation path

*First Packet*

| Field      | Type     | Content                | Expected  |
| ---------- | -------- | ---------------------- | --------- |
| Path[0]    | byte (4) | Derivation Path Data   | 44        |
| Path[1]    | byte (4) | Derivation Path Data   | 461       |
| Path[2]    | byte (4) | Derivation Path Data   | ?         |
| Path[3]    | byte (4) | Derivation Path Data   | ?         |
| Path[4]    | byte (4) | Derivation Path Data   | ?         |

*Other Chunks/Packets*

| Field   | Type     | Content         | Expected |
| ------- | -------- | --------------- | -------- |
| Data    | bytes... | Canister Call   |          |

#### Response

| Field   | Type      | Content     | Note                     |
| ------- | --------- | ----------- | ------------------------ |
| SW1-SW2 | byte (2)  | Return code | see list of return codes |

--------------

### INS_CERTIFICATE_AND_SIGN

#### Command

| Field   | Type     | Content                | Expected     |
| ------- | -------- | ---------------------- | ------------ |
| CLA     | byte (1) | Application Identifier | 0x11         |
| INS     | byte (1) | Instruction ID         | 0x06         |
| P1      | byte (1) | Payload desc           | 0 = init     |
|         |          |                        | 1 = add      |
|         |          |                        | 2 = last     |
| P2      | byte (1) | ----                   | ignored      |
| L       | byte (1) | Bytes in payload       | (depends)    |

The first packet/chunk includes only the derivation path

*First Packet*

| Field      | Type     | Content                | Expected  |
| ---------- | -------- | ---------------------- | --------- |
| Path[0]    | byte (4) | Derivation Path Data   | 44        |
| Path[1]    | byte (4) | Derivation Path Data   | 461       |
| Path[2]    | byte (4) | Derivation Path Data   | ?         |
| Path[3]    | byte (4) | Derivation Path Data   | ?         |
| Path[4]    | byte (4) | Derivation Path Data   | ?         |

*Other Chunks/Packets*

| Field   | Type     | Content          | Expected |
| ------- | -------- | ---------------- | -------- |
| Data    | bytes... | Certificate Data |          |

#### Response

| Field           | Type            | Content     | Note                     |
| --------------- | --------------- | ----------- | ------------------------ |
| secp256k1 R     | byte (32)       | Signature   |                          |
| secp256k1 S     | byte (32)       | Signature   |                          |
| secp256k1 V     | byte (1)        | Signature   |                          |
| SIG             | byte (variable) | Signature   | DER format               |
| SW1-SW2         | byte (2)        | Return code | see list of return codes |

--------------

### INS_SUPPORTED_TOKENS_LEN

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0x11     |
| INS   | byte (1) | Instruction ID         | 0x07     |
| P1    | byte (1) | Parameter 1            | ignored  |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field   | Type     | Content          | Note                                   |
| ------- | -------- | ---------------- | -------------------------------------- |
| LEN     | byte (1) | Number of tokens | Number of supported tokens in registry |
| SW1-SW2 | byte (2) | Return code      | see list of return codes               |

--------------

### INS_TOKEN_AT_IDX

#### Command

| Field | Type     | Content                | Expected |
| ----- | -------- | ---------------------- | -------- |
| CLA   | byte (1) | Application Identifier | 0x11     |
| INS   | byte (1) | Instruction ID         | 0x08     |
| P1    | byte (1) | Token Index            | 0-255    |
| P2    | byte (1) | Parameter 2            | ignored  |
| L     | byte (1) | Bytes in payload       | 0        |

#### Response

| Field   | Type     | Content          | Note                     |
| ------- | -------- | ---------------- | ------------------------ |
| TOKEN_INFO | byte (?) | Token Information | See TokenInfo structure  |
| SW1-SW2 | byte (2) | Return code      | see list of return codes |

#### TokenInfo Structure

The token information is returned as an array of the following structure:

| Field        | Type     | Content                |
| ------------ | -------- | ---------------------- |
| TOKEN_SYMBOL | byte (?) | Token symbol string    |
| TOKEN_NAME   | byte (?) | Token name string      |
| DECIMALS     | byte (1) | Number of decimals     |

The array length is determined by the number of supported tokens, which can be obtained using the `INS_SUPPORTED_TOKENS_LEN` command.
