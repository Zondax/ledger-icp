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

            const expected_principalTextual = "5upke-tazvi-6ufqc-i3v6r-j4gpu-dpwti-obhal-yb5xj-ue32x-ktkql-rqe";
            const expected_principal = "19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302";
            const expected_pk = "0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835";
            const expected_address = "4f3d4b40cdb852732601fccf8bd24dffe44957a647cb867913e982d98cf85676"

            expect(resp.principal).toEqual(expected_principal);
            expect(resp.principalText).toEqual(expected_principalTextual);
            expect(resp.publicKey).toEqual(expected_pk);
            expect(resp.address).toEqual(expected_address);

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

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-show_address`, model === "nanos" ? 4 : 5);

            const resp = await respRequest;

            console.log(resp)

            expect(resp.returnCode).toEqual(0x9000);
            expect(resp.errorMessage).toEqual("No errors");

            const expected_principalTextual = "5upke-tazvi-6ufqc-i3v6r-j4gpu-dpwti-obhal-yb5xj-ue32x-ktkql-rqe";
            const expected_principal = "19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302";
            const expected_pk = "0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835";
            const expected_address = "4f3d4b40cdb852732601fccf8bd24dffe44957a647cb867913e982d98cf85676"

            expect(resp.principal).toEqual(expected_principal);
            expect(resp.principalText).toEqual(expected_principalTextual);
            expect(resp.publicKey).toEqual(expected_pk);
            expect(resp.address).toEqual(expected_address);
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

            let txBlobStr = "d9d9f7a367636f6e74656e74a76c726571756573745f747970656463616c6c656e6f6e636550f5390d960c6e52f489155a4309da03da6e696e67726573735f6578706972791b1674c5e29ec9c2106673656e646572581d7bdd7f75eea6fcf58001e0dfb7d718b9e8f2c3b01e1ccec9ab305aad026b63616e69737465725f69644a000000000000000201016b6d6574686f645f6e616d656473656e646361726758560a0012050a0308e8071a0308890122220a2001010101010101010101010101010101010101010101010101010101010101012a220a2035548ec29e9d85305850e87a2d2642fe7214ff4bb36334070deafc3345c3b1276d73656e6465725f7075626b657958583056301006072a8648ce3d020106052b8104000a03420004e1142e1fbc940344d9161709196bb8bd151f94379c48dd507ab99a0776109128b94b5303cf2b2d28e25a779da175b62f8a975599b20c63d5193202640576ec5e6a73656e6465725f7369675840de5bccbb0a0173c432cd58ea4495d4d1e122d6ce04e31dcf63217f3d3a9b73130dc9bbf3b10e61c8db8bf8800bb4649e27786e5bc9418838c95864be28487a6a";

            const txBlob = Buffer.from(txBlobStr, "hex");

            const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_basic_normal`, model === "nanos" ? 13 : 12);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            const expected_preHash = "0a69632d726571756573747058c3bd4323237852f94f4dfa923e3f26080679619140014356f3d6c48e674b";
            expect(signatureResponse.preSignHash.toString('hex')).toEqual(expected_preHash);

            const expected_hash = "e5447f8722832acaaa07ee554d1807886db485043529f505adad17e32050a1fc";
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

            let txBlobStr = "d9d9f7a367636f6e74656e74a46c726571756573745f747970656a726561645f73746174656e696e67726573735f6578706972791b1674c5e2b4d947b06673656e646572581d7bdd7f75eea6fcf58001e0dfb7d718b9e8f2c3b01e1ccec9ab305aad0265706174687381824e726571756573745f73746174757358207058c3bd4323237852f94f4dfa923e3f26080679619140014356f3d6c48e674b6d73656e6465725f7075626b657958583056301006072a8648ce3d020106052b8104000a03420004e1142e1fbc940344d9161709196bb8bd151f94379c48dd507ab99a0776109128b94b5303cf2b2d28e25a779da175b62f8a975599b20c63d5193202640576ec5e6a73656e6465725f73696758403c850f1f7d6ae07777ca077dbb7fe2a21d9e5c38494dc17d2e1736ed760d1db222688979769d978153ee4e0420af5c5052f0de5acba20e6a0865414f048ffa61";
            const txBlob = Buffer.from(txBlobStr, "hex");

            const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob);

            // Wait until we are not in the main menu
            await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot());

            await sim.compareSnapshotsAndAccept(".", `${prefix.toLowerCase()}-sign_stateread_normal`, model === "nanos" ? 7 : 8);

            let signatureResponse = await respRequest;
            console.log(signatureResponse);

            expect(signatureResponse.returnCode).toEqual(0x9000);
            expect(signatureResponse.errorMessage).toEqual("No errors");

            const expected_preHash = "0a69632d7265717565737494a6b4c7dd97a1d04f7428b26ecca2b55c049fa473c23f0792bf5267bc45033f";
            expect(signatureResponse.preSignHash.toString('hex')).toEqual(expected_preHash);

            const expected_hash = "f8e8810b6b826d5335b02d3a597abc8abececa7bbe01c094c5959c1f74832274";
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
