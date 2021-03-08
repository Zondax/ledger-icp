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

            const expected_address = "a275407a1070096ee5d8bd00d711a4c7904ca28fbbe592dc68d77d4d02";
            const expected_pk = "0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835";

            expect(resp.address).toEqual(expected_address);
            expect(resp.publicKey).toEqual(expected_pk);
        } finally {
            await sim.close();
        }
    });
});
