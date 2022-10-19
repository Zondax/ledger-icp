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

import Zemu from '@zondax/zemu'
import InternetComputerApp from '@zondax/ledger-icp'
import {SIGN_VALUES_P2} from "@zondax/ledger-icp/dist/common";
import {DEFAULT_OPTIONS, DEVICE_MODELS} from "./common";

jest.setTimeout(180000)

beforeAll(async () => {
  await Zemu.checkAndPullImage()
})

describe('Phase2', function () {
  test.each(DEVICE_MODELS)('sign normal -- split', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a6636172675903334449444c426c01dbb701786e006e686e786c02dbe2be950902ef9999fe09036c01b9ef938008786d006c02afa3bda10175c2cee0d80c066c006c029cb1fa2502ba89e5c204786b039ef5cc0f089992ccd00109dae1c99903786e0a6c01d7ab010b6c01f6b0989a08026c018eddc3a60d026c018dc3b2b303796c01c88ecad50a786b0796a7f7150df381d4ab020eb09b9ba40708d0fb87af070890f29afe070fe4ac938d0c08c3a2f6c90e106e116c01a78882820a126c02ea99cff20475b2b8d4960b016c01c38fbbd10b016c05f5bbe3900178d2bbf0d9017eb9ef93800878dbe2be950902ef9999fe09786c04efd6e4027198abec810118b6f798b2013ea696a48708716e716c02cbe4fdc70471fc91f4f805186e196c02dbb70101bac7a7fa0d1a6c01b99d9da50b796d7b6c01cedfa0a8041d6e1e6c01e0a9b302786e206c02a9ddf49b071fd8a38ca80d216b0b9b9cd0a40104bab5f1a40105918bacf10207fc9fc683050cc6b3bb9106138db2d592091498a5d0c7091591b2fab80a16e0f8fffd0b1789b8b3b30e1ca3f3c0ad0f226e236b02cd8e8eb9041dcebee1d308006e256c03dbb70101cbe2b58b0824f1bb8b880d266c02e4d7bee905758effd6e90e1d6c02dbb701029df1afe7071f6e296c01f5bbe39001786c01a9ddf49b071f6b02fdf59aec0b2be3b586ff0c2c6e2d6c03ce9ca6ce012af382ccb3072eb9ef938008786c01c2cee0d80c066c02007501306d316c0184aead33326d2f6c01a4ccf7dd0a346c089eb493cf0378befa8dd40479be8fe6e30478ce89be97067886f998bc0978c5cae3d40a7893a190e00c78f5e1d0e70d786d686c018594e2c50b376b02bf80e42b29c6a6e4b90a296e396c01f0a2cabb0b3a6c0196bdb4e904716b0a93a7e09d021bd881c9c40327d69ce79d0a2882ffcfaa0c2fe3c3c5990e33b1a5aea10e35f5d9d7a50e36fad5ddf40e38db9cebf70e3bd6f4c7ff0f3c6e3d6b0b9b9cd0a40104bab5f1a40105918bacf10207fc9fc683050cc6b3bb9106138db2d592091498a5d0c7091591b2fab80a16e0f8fffd0b1789b8b3b30e1ca3f3c0ad0f226e3f6c03dbb70101cbe2b58b08c000f1bb8b880d2601c10000010100e1f50500000000010115cd5b07000000006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16d048c672ae96c06b6d6574686f645f6e616d656d6d616e6167655f6e6575726f6e6c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_split`, m.name === 'nanos' ? 3 : 4)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      sim.dumpEvents()
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('sign normal -- merge', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
        'd9d9f7a167636f6e74656e74a6636172675903344449444c426c01dbb701786e006e686e786c02dbe2be950902ef9999fe09036c01b9ef938008786d006c02afa3bda10175c2cee0d80c066c006c029cb1fa2502ba89e5c204786b039ef5cc0f089992ccd00109dae1c99903786e0a6c01d7ab010b6c01f6b0989a08026c018eddc3a60d026c018dc3b2b303796c01c88ecad50a786b0796a7f7150df381d4ab020eb09b9ba40708d0fb87af070890f29afe070fe4ac938d0c08c3a2f6c90e106e116c01a78882820a126c02ea99cff20475b2b8d4960b016c01c38fbbd10b016c05f5bbe3900178d2bbf0d9017eb9ef93800878dbe2be950902ef9999fe09786c04efd6e4027198abec810118b6f798b2013ea696a48708716e716c02cbe4fdc70471fc91f4f805186e196c02dbb70101bac7a7fa0d1a6c01b99d9da50b796d7b6c01cedfa0a8041d6e1e6c01e0a9b302786e206c02a9ddf49b071fd8a38ca80d216b0b9b9cd0a40104bab5f1a40105918bacf10207fc9fc683050cc6b3bb9106138db2d592091498a5d0c7091591b2fab80a16e0f8fffd0b1789b8b3b30e1ca3f3c0ad0f226e236b02cd8e8eb9041dcebee1d308006e256c03dbb70101cbe2b58b0824f1bb8b880d266c02e4d7bee905758effd6e90e1d6c02dbb701029df1afe7071f6e296c01f5bbe39001786c01a9ddf49b071f6b02fdf59aec0b2be3b586ff0c2c6e2d6c03ce9ca6ce012af382ccb3072eb9ef938008786c01c2cee0d80c066c02007501306d316c0184aead33326d2f6c01a4ccf7dd0a346c089eb493cf0378befa8dd40479be8fe6e30478ce89be97067886f998bc0978c5cae3d40a7893a190e00c78f5e1d0e70d786d686c018594e2c50b376b02bf80e42b29c6a6e4b90a296e396c01f0a2cabb0b3a6c0196bdb4e904716b0a93a7e09d021bd881c9c40327d69ce79d0a2882ffcfaa0c2fe3c3c5990e33b1a5aea10e35f5d9d7a50e36fad5ddf40e38db9cebf70e3bd6f4c7ff0f3c6e3d6b0b9b9cd0a40104bab5f1a40105918bacf10207fc9fc683050cc6b3bb9106138db2d592091498a5d0c7091591b2fab80a16e0f8fffd0b1789b8b3b30e1ca3f3c0ad0f226e3f6c03dbb70101cbe2b58b08c000f1bb8b880d2601c100000106017b000000000000000101c8010000000000006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16d09dc450eb9bc06b6d6574686f645f6e616d656d6d616e6167655f6e6575726f6e6c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_merge`)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      sim.dumpEvents()
      await sim.close()
    }
  })
})
