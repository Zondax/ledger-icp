/** ******************************************************************************
 *  (c) 2020 Zondax GmbH
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

import jest, {expect} from "jest";
import Zemu from "@zondax/zemu";
import DfinityApp from "@zondax/ledger-dfinity";
import * as secp256k1 from "secp256k1";
var sha256 = require('js-sha256');

const Resolve = require("path").resolve;
const APP_PATH_S = Resolve("../app/output/app_s.elf");
const APP_PATH_X = Resolve("../app/output/app_x.elf");

const APP_SEED = "equip will roof matter pink blind book anxiety banner elbow sun young"

var simOptions = {
    logging: true,
    start_delay: 3000,
    custom: `-s "${APP_SEED}"`,
    X11: false
};

let models = [
    ['S', {model: 'nanos', prefix: 'S', path: APP_PATH_S}],
    ['X', {model: 'nanox', prefix: 'X', path: APP_PATH_X}]
]

jest.setTimeout(60000)

const SIGN_TYPE = {
    TOKEN_TRANSFER: 0x00,
    STATE_TRANSACTION_READ: 0x01,
};

describe('Standard', function () {
    test.each(models)('can start and stop container (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
        } finally {
            await sim.close();
        }
    });

    test.each(models)('main menu (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-mainmenu`, 3);
        } finally {
            await sim.close();
        }
    });

    test.each(models)('get app version (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new DfinityApp(sim.getTransport());
            const resp = await app.getVersion();

            console.log(resp);

            expect(resp.returnCode).toEqual(0x9000);
            expect(resp.errorMessage).toEqual("No errors");
            expect(resp).toHaveProperty("testMode");
            expect(resp).toHaveProperty("major");
            expect(resp).toHaveProperty("minor");
            expect(resp).toHaveProperty("patch");
        } finally {
            await sim.close();
        }
    });

    test.each(models)('get address (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new DfinityApp(sim.getTransport());

            const resp = await app.getAddressAndPubKey("m/44'/223'/0'/0/0");

            console.log(resp)

            expect(resp.returnCode).toEqual(0x9000);
            expect(resp.errorMessage).toEqual("No errors");

            const expected_addressTextual = "5upke-tazvi-6ufqc-i3v6r-j4gpu-dpwti-obhal-yb5xj-ue32x-ktkql-rqe";
            const expected_address = "19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302";
            const expected_pk = "0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835";

            expect(resp.addressText).toEqual(expected_addressTextual);
            expect(resp.address).toEqual(expected_address);
            expect(resp.publicKey).toEqual(expected_pk);
        } finally {
            await sim.close();
        }
    });

    test.each(models)('show address (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new DfinityApp(sim.getTransport());

            const respRequest = app.showAddressAndPubKey("m/44'/223'/0'/0/0");

            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-show_address`, model === "nanos" ? 2 : 3);

            const resp = await respRequest;

            console.log(resp)

            expect(resp.returnCode).toEqual(0x9000);
            expect(resp.errorMessage).toEqual("No errors");

            const expected_addressTextual = "5upke-tazvi-6ufqc-i3v6r-j4gpu-dpwti-obhal-yb5xj-ue32x-ktkql-rqe";
            const expected_address = "19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302";
            const expected_pk = "0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835";

            expect(resp.addressText).toEqual(expected_addressTextual);
            expect(resp.address).toEqual(expected_address);
            expect(resp.publicKey).toEqual(expected_pk);
        } finally {
            await sim.close();
        }
    });

    test.each(models)('sign basic normal (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new DfinityApp(sim.getTransport());

            const respAddr = await app.getAddressAndPubKey("m/44'/223'/0'/0/0");
            console.log(respAddr)

            expect(respAddr.returnCode).toEqual(0x9000);
            expect(respAddr.errorMessage).toEqual("No errors");

            const expected_pk = "0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835";
            expect(respAddr.publicKey).toEqual(expected_pk);

            let txBlobStr = "d9d9f7a367636f6e74656e74a76c726571756573745f747970656463616c6c656e6f6e636550e063ee93160f37ee2216b6a2a28119a46e696e67726573735f6578706972791b166b1ab6ec9c35086673656e646572581d45717a3a0e68fceef546ac77bac551754b48dbb1fccfa180673030b6026b63616e69737465725f69644a000000000000000a01016b6d6574686f645f6e616d656473656e646361726758474449444c026c04fbca0171c6fcb60201ba89e5c2047cd8a38ca80d016c01b1dfb793047c01001b72776c67742d69696161612d61616161612d61616161612d636169880100e8076d73656e6465725f7075626b6579582c302a300506032b6570032100e29472cb531fdb17386dae5f5a6481b661eb3ac4b4982c638c91f7716c2c96e76a73656e6465725f736967584084dc1f2e7338eac3eae5967ddf6074a8f6c2d98e598f481a807569c9219b94d4175bed43e8d25bde1b411c4f50b9fe23e1c521ec53f3c2f80fa4621b27292208";
            const txBlob = Buffer.from(txBlobStr, "hex");

            const respRequest = app.sign("m/44'/223'/0'/0/0", SIGN_TYPE.TOKENTRANSFER, txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_normal`, model === "nanos" ? 8 : 9);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            const expected_preHash = "0a69632d72657175657374bf5bae8c2b6be8103a070e6d2240c18788c10a94ba68990f8c7e7acecb8b8c34";
            expect(signatureResponse.preSignHash.toString('hex')).toEqual(expected_preHash);

            const expected_hash = "084544f8f1852065408e18c5bc595e07c49e44085728833a822b24487eb4e191";
            let hash = sha256.hex(signatureResponse.preSignHash);
            expect(hash).toEqual(expected_hash);

            const pk = Uint8Array.from(Buffer.from(respAddr.publicKey.toString(), 'hex'))
            expect(pk.byteLength).toEqual(65);
            const digest = Uint8Array.from(Buffer.from(hash, 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRS);
            //const signature = secp256k1.signatureImport(Uint8Array.from(signatureResponse.signatureDER));
            expect(signature.byteLength).toEqual(64);

            const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });

    test.each(models)('sign state transaction read (%s)', async function (_, {model, prefix, path}) {
        const sim = new Zemu(path);
        try {
            await sim.start({model, ...simOptions});
            const app = new DfinityApp(sim.getTransport());

            const respAddr = await app.getAddressAndPubKey("m/44'/223'/0'/0/0");
            console.log(respAddr)

            expect(respAddr.returnCode).toEqual(0x9000);
            expect(respAddr.errorMessage).toEqual("No errors");

            const expected_pk = "0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835";
            expect(respAddr.publicKey).toEqual(expected_pk);

            let txBlobStr = "d9d9f7a367636f6e74656e74a46c726571756573745f747970656a726561645f73746174656e696e67726573735f6578706972791b166f4469eeb674586673656e646572581d45717a3a0e68fceef546ac77bac551754b48dbb1fccfa180673030b60265706174687381824e726571756573745f737461747573582062af1451c511bc05819de49a5e271ad77d4cd9624da4a3bdf2e45d0ae35e72826d73656e6465725f7075626b6579582c302a300506032b6570032100e29472cb531fdb17386dae5f5a6481b661eb3ac4b4982c638c91f7716c2c96e76a73656e6465725f73696758401a48a2202c5d968a693b310c71207577c7c9f43d6596f4e828e47587170e60faf4171982e3fcad7109ccada265ffd3d2132b0d8a26e8013478b0ded5861d1d03";
            const txBlob = Buffer.from(txBlobStr, "hex");

            const respRequest = app.sign("m/44'/223'/0'/0/0", SIGN_TYPE.STATE_TRANSACTION_READ, txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_stateread_normal`, model === "nanos" ? 6 : 7);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            const expected_preHash = "0a69632d726571756573743cb781c142e069f99a314a25b7b8878e6f44df86e1731913fd41dd653f71be65";
            expect(signatureResponse.preSignHash.toString('hex')).toEqual(expected_preHash);

            const expected_hash = "73259b1a36f71964e4e17a9794516f684ef4a8ce61635d4d113c50e4618999df";
            let hash = sha256.hex(signatureResponse.preSignHash);
            expect(hash).toEqual(expected_hash);

            const pk = Uint8Array.from(Buffer.from(respAddr.publicKey.toString(), 'hex'))
            expect(pk.byteLength).toEqual(65);
            const digest = Uint8Array.from(Buffer.from(hash, 'hex'));
            const signature = Uint8Array.from(signatureResponse.signatureRS);
            //const signature = secp256k1.signatureImport(Uint8Array.from(signatureResponse.signatureDER));
            expect(signature.byteLength).toEqual(64);

            const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk);
            expect(signatureOk).toEqual(true);

        } finally {
            await sim.close();
        }
    });

});
