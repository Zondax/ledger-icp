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
import InternetComputerApp, { SIGN_VALUES_P2 } from '@zondax/ledger-icp'
import { DEFAULT_OPTIONS, DEVICE_MODELS } from './common'

jest.setTimeout(180000)

const path = "m/44'/223'/0'/0/0"

describe('Phase2', function () {
  test.concurrent.each(DEVICE_MODELS)('sign normal -- split', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
        'd9d9f7a167636f6e74656e74a6636172675903334449444c426c01dbb701786e006e686e786c02dbe2be950902ef9999fe09036c01b9ef938008786d006c02afa3bda10175c2cee0d80c066c006c029cb1fa2502ba89e5c204786b039ef5cc0f089992ccd00109dae1c99903786e0a6c01d7ab010b6c01f6b0989a08026c018eddc3a60d026c018dc3b2b303796c01c88ecad50a786b0796a7f7150df381d4ab020eb09b9ba40708d0fb87af070890f29afe070fe4ac938d0c08c3a2f6c90e106e116c01a78882820a126c02ea99cff20475b2b8d4960b016c01c38fbbd10b016c05f5bbe3900178d2bbf0d9017eb9ef93800878dbe2be950902ef9999fe09786c04efd6e4027198abec810118b6f798b2013ea696a48708716e716c02cbe4fdc70471fc91f4f805186e196c02dbb70101bac7a7fa0d1a6c01b99d9da50b796d7b6c01cedfa0a8041d6e1e6c01e0a9b302786e206c02a9ddf49b071fd8a38ca80d216b0b9b9cd0a40104bab5f1a40105918bacf10207fc9fc683050cc6b3bb9106138db2d592091498a5d0c7091591b2fab80a16e0f8fffd0b1789b8b3b30e1ca3f3c0ad0f226e236b02cd8e8eb9041dcebee1d308006e256c03dbb70101cbe2b58b0824f1bb8b880d266c02e4d7bee905758effd6e90e1d6c02dbb701029df1afe7071f6e296c01f5bbe39001786c01a9ddf49b071f6b02fdf59aec0b2be3b586ff0c2c6e2d6c03ce9ca6ce012af382ccb3072eb9ef938008786c01c2cee0d80c066c02007501306d316c0184aead33326d2f6c01a4ccf7dd0a346c089eb493cf0378befa8dd40479be8fe6e30478ce89be97067886f998bc0978c5cae3d40a7893a190e00c78f5e1d0e70d786d686c018594e2c50b376b02bf80e42b29c6a6e4b90a296e396c01f0a2cabb0b3a6c0196bdb4e904716b0a93a7e09d021bd881c9c40327d69ce79d0a2882ffcfaa0c2fe3c3c5990e33b1a5aea10e35f5d9d7a50e36fad5ddf40e38db9cebf70e3bd6f4c7ff0f3c6e3d6b0b9b9cd0a40104bab5f1a40105918bacf10207fc9fc683050cc6b3bb9106138db2d592091498a5d0c7091591b2fab80a16e0f8fffd0b1789b8b3b30e1ca3f3c0ad0f226e3f6c03dbb70101cbe2b58b08c000f1bb8b880d2601c10000010100e1f50500000000010115cd5b07000000006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16d048c672ae96c06b6d6574686f645f6e616d656d6d616e6167655f6e6575726f6e6c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign(path, txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_split`)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')
    } finally {
      sim.dumpEvents()
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('sign normal -- merge', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
        'd9d9f7a167636f6e74656e74a6636172675903344449444c426c01dbb701786e006e686e786c02dbe2be950902ef9999fe09036c01b9ef938008786d006c02afa3bda10175c2cee0d80c066c006c029cb1fa2502ba89e5c204786b039ef5cc0f089992ccd00109dae1c99903786e0a6c01d7ab010b6c01f6b0989a08026c018eddc3a60d026c018dc3b2b303796c01c88ecad50a786b0796a7f7150df381d4ab020eb09b9ba40708d0fb87af070890f29afe070fe4ac938d0c08c3a2f6c90e106e116c01a78882820a126c02ea99cff20475b2b8d4960b016c01c38fbbd10b016c05f5bbe3900178d2bbf0d9017eb9ef93800878dbe2be950902ef9999fe09786c04efd6e4027198abec810118b6f798b2013ea696a48708716e716c02cbe4fdc70471fc91f4f805186e196c02dbb70101bac7a7fa0d1a6c01b99d9da50b796d7b6c01cedfa0a8041d6e1e6c01e0a9b302786e206c02a9ddf49b071fd8a38ca80d216b0b9b9cd0a40104bab5f1a40105918bacf10207fc9fc683050cc6b3bb9106138db2d592091498a5d0c7091591b2fab80a16e0f8fffd0b1789b8b3b30e1ca3f3c0ad0f226e236b02cd8e8eb9041dcebee1d308006e256c03dbb70101cbe2b58b0824f1bb8b880d266c02e4d7bee905758effd6e90e1d6c02dbb701029df1afe7071f6e296c01f5bbe39001786c01a9ddf49b071f6b02fdf59aec0b2be3b586ff0c2c6e2d6c03ce9ca6ce012af382ccb3072eb9ef938008786c01c2cee0d80c066c02007501306d316c0184aead33326d2f6c01a4ccf7dd0a346c089eb493cf0378befa8dd40479be8fe6e30478ce89be97067886f998bc0978c5cae3d40a7893a190e00c78f5e1d0e70d786d686c018594e2c50b376b02bf80e42b29c6a6e4b90a296e396c01f0a2cabb0b3a6c0196bdb4e904716b0a93a7e09d021bd881c9c40327d69ce79d0a2882ffcfaa0c2fe3c3c5990e33b1a5aea10e35f5d9d7a50e36fad5ddf40e38db9cebf70e3bd6f4c7ff0f3c6e3d6b0b9b9cd0a40104bab5f1a40105918bacf10207fc9fc683050cc6b3bb9106138db2d592091498a5d0c7091591b2fab80a16e0f8fffd0b1789b8b3b30e1ca3f3c0ad0f226e3f6c03dbb70101cbe2b58b08c000f1bb8b880d2601c100000106017b000000000000000101c8010000000000006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16d09dc450eb9bc06b6d6574686f645f6e616d656d6d616e6167655f6e6575726f6e6c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign(path, txBlob, SIGN_VALUES_P2.DEFAULT)

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

  test.concurrent.each(DEVICE_MODELS)('sign normal -- set dissolve delay', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      // Args bigger than 1000 bytes
      const txBlobStr =
        'd9d9f7a167636f6e74656e74a7636172675904044449444c506c01dbb701786e006e796e686e786c03bc949d820302dbe2be950903ef9999fe09046c01b9ef938008786d006c02afa3bda10175c2cee0d80c076c006c029cb1fa2503ba89e5c204786b039ef5cc0f099992ccd0010adae1c99903786e0b6c01d7ab010c6c01f6b0989a08036c018eddc3a60d036c01d0e1e9f60c7e6c018dc3b2b303796c01c88ecad50a786b0996a7f7150ef381d4ab020f8cb2f18c0710b09b9ba40709d0fb87af070990f29afe0711e4ac938d0c09f7aacfd80d09c3a2f6c90e126e136c01a78882820a146c02ea99cff20475b2b8d4960b016c01c38fbbd10b016c05f5bbe3900178d2bbf0d9017eb9ef93800878dbe2be950903ef9999fe09786c04efd6e4027198abec81011ab6f798b201cc00a696a48708716e716c02cbe4fdc70471fc91f4f8051a6e1b6c02dbb70101bac7a7fa0d1c6c01bbb4b09703026c01b99d9da50b796d7b6c01cedfa0a804206e216c01e0a9b302786e236c02a9ddf49b0722d8a38ca80d246b0c9b9cd0a40105bab5f1a40106918bacf10208fc9fc683050dc6b3bb9106158db2d592091698a5d0c7091791b2fab80a18e0f8fffd0b198bf3afac0d1e89b8b3b30e1fa3f3c0ad0f256e266b02cd8e8eb90420cebee1d308006e286c03dbb70101cbe2b58b0827f1bb8b880d296c02e4d7bee905758effd6e90e206c02dbb701039df1afe707226e2c6c01f5bbe39001786c01a9ddf49b07226b02fdf59aec0b2ee3b586ff0c2f6e306c03ce9ca6ce012df382ccb30731b9ef938008786c028fa0804178cf898dd304786e336c08fed391bd0178abe1b1d00134dcd0a0ab0378dfbcb4d80478edc6ecab087993e5e481097890b090af0e78ca9ab7d20f786e356c03d889bea60d04b5f6f9e90e03c6f6ebeb0e366c02f9889a5778b2cc99e705786e386c01edbb85f901396e3a6c02cfbe93a4043bc796cdbe0b036c01c2cee0d80c076c020075013d6d3e6c0184aead333f6e7e6d326c02f8b9b6c904c100a4ccf7dd0ac2006c089eb493cf0378befa8dd40479be8fe6e30478ce89be97067886f998bc0978c5cae3d40a7893a190e00c78f5e1d0e70d786d686c018594e2c50bc5006b02bf80e42b2cc6a6e4b90a2c6ec7006c01f0a2cabb0bc8006c0196bdb4e904716b0c93a7e09d021dd881c9c4032ad69ce79d0a2b82ffcfaa0c329e9598a00d379dfa94a40d3ce3c3c5990ec000b1a5aea10ec300f5d9d7a50ec400fad5ddf40ec600db9cebf70ec900d6f4c7ff0fca006ecb006b0c9b9cd0a40105bab5f1a40106918bacf10208fc9fc683050dc6b3bb9106158db2d592091698a5d0c7091791b2fab80a18e0f8fffd0b198bf3afac0d1e89b8b3b30e1fa3f3c0ad0f256ecd006c03dbb70101cbe2b58b08ce00f1bb8b880d2901cf0001d843d60486d084150104010868973a6500000000006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b172198c3df1c1b406b6d6574686f645f6e616d656d6d616e6167655f6e6575726f6e656e6f6e6365500000018413e4abc5061f49e2686dc47c6c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign(path, txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_set_dissolve_delay`)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')
    } finally {
      sim.dumpEvents()
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('sign normal -- spawn neuron candid', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
        'd9d9f7a167636f6e74656e74a6636172675904114449444c4e6c01dbb701786e006e796e686e786c03bc949d820302dbe2be950903ef9999fe09046c01b9ef938008786d006c02afa3bda10175c2cee0d80c076c006c029cb1fa2503ba89e5c204786b039ef5cc0f099992ccd0010adae1c99903786e0b6c01d7ab010c6c01f6b0989a08036c018eddc3a60d036c01d0e1e9f60c7e6c018dc3b2b303796c01c88ecad50a786b0996a7f7150ef381d4ab020f8cb2f18c0710b09b9ba40709d0fb87af070990f29afe0711e4ac938d0c09f7aacfd80d09c3a2f6c90e126e136c01a78882820a146c02ea99cff20475b2b8d4960b016c01c38fbbd10b016c05f5bbe3900178d2bbf0d9017eb9ef93800878dbe2be950903ef9999fe09786c04efd6e4027198abec81011ab6f798b201ca00a696a48708716e716c02cbe4fdc70471fc91f4f8051a6e1b6c02dbb70101bac7a7fa0d1c6c01bbb4b09703026c01b99d9da50b796d7b6c01cedfa0a804206e216c01e0a9b302786e236c02a9ddf49b0722d8a38ca80d246b0c9b9cd0a40105bab5f1a40106918bacf10208fc9fc683050dc6b3bb9106158db2d592091698a5d0c7091791b2fab80a18e0f8fffd0b198bf3afac0d1e89b8b3b30e1fa3f3c0ad0f256e266b02cd8e8eb90420cebee1d308006e286c03dbb70101cbe2b58b0827f1bb8b880d296c02e4d7bee905758effd6e90e206c02dbb701039df1afe707226e2c6c01f5bbe39001786c01a9ddf49b07226b02fdf59aec0b2ee3b586ff0c2f6e306c03ce9ca6ce012df382ccb30731b9ef938008786c07fed391bd0178dcd0a0ab0378dfbcb4d80478edc6ecab087993e5e481097890b090af0e78ca9ab7d20f786e336c03d889bea60d04b5f6f9e90e03c6f6ebeb0e346c02f9889a5778b2cc99e705786e366c01edbb85f901376e386c02cfbe93a40439c796cdbe0b036c01c2cee0d80c076c020075013b6d3c6c0184aead333d6e7e6d326c02f8b9b6c9043fa4ccf7dd0ac0006c089eb493cf0378befa8dd40479be8fe6e30478ce89be97067886f998bc0978c5cae3d40a7893a190e00c78f5e1d0e70d786d686c018594e2c50bc3006b02bf80e42b2cc6a6e4b90a2c6ec5006c01f0a2cabb0bc6006c0196bdb4e904716b0c93a7e09d021dd881c9c4032ad69ce79d0a2b82ffcfaa0c329e9598a00d359dfa94a40d3ae3c3c5990e3eb1a5aea10ec100f5d9d7a50ec200fad5ddf40ec400db9cebf70ec700d6f4c7ff0fc8006ec9006b0c9b9cd0a40105bab5f1a40106918bacf10208fc9fc683050dc6b3bb9106158db2d592091698a5d0c7091791b2fab80a18e0f8fffd0b198bf3afac0d1e89b8b3b30e1fa3f3c0ad0f256ecb006c03dbb70101cbe2b58b08cc00f1bb8b880d2901cd000100406c4830c8a17a0100011e00000001011d4e9644473effb4cd436eec1a9c8c08168021f63879c97d1f6fdc89dd02013930000000000000006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b172cfa155781e8406b6d6574686f645f6e616d656d6d616e6167655f6e6575726f6e6c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign(path, txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_spawn_neuron_candid`)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')
    } finally {
      sim.dumpEvents()
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('sign normal -- list neurons candid', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
        'd9d9f7a167636f6e74656e74a66361726758294449444c026d786c02acbe9cc50700dabcd1c70d7e01010200c8c056ea395dd500406c4830c8a17a006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b172cfa0381138f406b6d6574686f645f6e616d656c6c6973745f6e6575726f6e736c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign(path, txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_list_neurons_candid`)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')
    } finally {
      sim.dumpEvents()
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('sign normal -- stake maturity candid', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
        'd9d9f7a167636f6e74656e74a6636172675903e84449444c4e6c01dbb701786e006e796e686e786c03bc949d820302dbe2be950903ef9999fe09046c01b9ef938008786d006c02afa3bda10175c2cee0d80c076c006c029cb1fa2503ba89e5c204786b039ef5cc0f099992ccd0010adae1c99903786e0b6c01d7ab010c6c01f6b0989a08036c018eddc3a60d036c01d0e1e9f60c7e6c018dc3b2b303796c01c88ecad50a786b0996a7f7150ef381d4ab020f8cb2f18c0710b09b9ba40709d0fb87af070990f29afe0711e4ac938d0c09f7aacfd80d09c3a2f6c90e126e136c01a78882820a146c02ea99cff20475b2b8d4960b016c01c38fbbd10b016c05f5bbe3900178d2bbf0d9017eb9ef93800878dbe2be950903ef9999fe09786c04efd6e4027198abec81011ab6f798b201ca00a696a48708716e716c02cbe4fdc70471fc91f4f8051a6e1b6c02dbb70101bac7a7fa0d1c6c01bbb4b09703026c01b99d9da50b796d7b6c01cedfa0a804206e216c01e0a9b302786e236c02a9ddf49b0722d8a38ca80d246b0c9b9cd0a40105bab5f1a40106918bacf10208fc9fc683050dc6b3bb9106158db2d592091698a5d0c7091791b2fab80a18e0f8fffd0b198bf3afac0d1e89b8b3b30e1fa3f3c0ad0f256e266b02cd8e8eb90420cebee1d308006e286c03dbb70101cbe2b58b0827f1bb8b880d296c02e4d7bee905758effd6e90e206c02dbb701039df1afe707226e2c6c01f5bbe39001786c01a9ddf49b07226b02fdf59aec0b2ee3b586ff0c2f6e306c03ce9ca6ce012df382ccb30731b9ef938008786c07fed391bd0178dcd0a0ab0378dfbcb4d80478edc6ecab087993e5e481097890b090af0e78ca9ab7d20f786e336c03d889bea60d04b5f6f9e90e03c6f6ebeb0e346c02f9889a5778b2cc99e705786e366c01edbb85f901376e386c02cfbe93a40439c796cdbe0b036c01c2cee0d80c076c020075013b6d3c6c0184aead333d6e7e6d326c02f8b9b6c9043fa4ccf7dd0ac0006c089eb493cf0378befa8dd40479be8fe6e30478ce89be97067886f998bc0978c5cae3d40a7893a190e00c78f5e1d0e70d786d686c018594e2c50bc3006b02bf80e42b2cc6a6e4b90a2c6ec5006c01f0a2cabb0bc6006c0196bdb4e904716b0c93a7e09d021dd881c9c4032ad69ce79d0a2b82ffcfaa0c329e9598a00d359dfa94a40d3ae3c3c5990e3eb1a5aea10ec100f5d9d7a50ec200fad5ddf40ec400db9cebf70ec700d6f4c7ff0fc8006ec9006b0c9b9cd0a40105bab5f1a40106918bacf10208fc9fc683050dc6b3bb9106158db2d592091698a5d0c7091791b2fab80a18e0f8fffd0b198bf3afac0d1e89b8b3b30e1fa3f3c0ad0f256ecb006c03dbb70101cbe2b58b08cc00f1bb8b880d2901cd000100406c4830c8a17a0109011e000000006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b172cf99414612c006b6d6574686f645f6e616d656d6d616e6167655f6e6575726f6e6c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign(path, txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_stake_maturity_candid`)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')
    } finally {
      sim.dumpEvents()
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('sign normal -- auto stake maturity candid', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
        'd9d9f7a167636f6e74656e74a6636172675903e64449444c4e6c01dbb701786e006e796e686e786c03bc949d820302dbe2be950903ef9999fe09046c01b9ef938008786d006c02afa3bda10175c2cee0d80c076c006c029cb1fa2503ba89e5c204786b039ef5cc0f099992ccd0010adae1c99903786e0b6c01d7ab010c6c01f6b0989a08036c018eddc3a60d036c01d0e1e9f60c7e6c018dc3b2b303796c01c88ecad50a786b0996a7f7150ef381d4ab020f8cb2f18c0710b09b9ba40709d0fb87af070990f29afe0711e4ac938d0c09f7aacfd80d09c3a2f6c90e126e136c01a78882820a146c02ea99cff20475b2b8d4960b016c01c38fbbd10b016c05f5bbe3900178d2bbf0d9017eb9ef93800878dbe2be950903ef9999fe09786c04efd6e4027198abec81011ab6f798b201ca00a696a48708716e716c02cbe4fdc70471fc91f4f8051a6e1b6c02dbb70101bac7a7fa0d1c6c01bbb4b09703026c01b99d9da50b796d7b6c01cedfa0a804206e216c01e0a9b302786e236c02a9ddf49b0722d8a38ca80d246b0c9b9cd0a40105bab5f1a40106918bacf10208fc9fc683050dc6b3bb9106158db2d592091698a5d0c7091791b2fab80a18e0f8fffd0b198bf3afac0d1e89b8b3b30e1fa3f3c0ad0f256e266b02cd8e8eb90420cebee1d308006e286c03dbb70101cbe2b58b0827f1bb8b880d296c02e4d7bee905758effd6e90e206c02dbb701039df1afe707226e2c6c01f5bbe39001786c01a9ddf49b07226b02fdf59aec0b2ee3b586ff0c2f6e306c03ce9ca6ce012df382ccb30731b9ef938008786c07fed391bd0178dcd0a0ab0378dfbcb4d80478edc6ecab087993e5e481097890b090af0e78ca9ab7d20f786e336c03d889bea60d04b5f6f9e90e03c6f6ebeb0e346c02f9889a5778b2cc99e705786e366c01edbb85f901376e386c02cfbe93a40439c796cdbe0b036c01c2cee0d80c076c020075013b6d3c6c0184aead333d6e7e6d326c02f8b9b6c9043fa4ccf7dd0ac0006c089eb493cf0378befa8dd40479be8fe6e30478ce89be97067886f998bc0978c5cae3d40a7893a190e00c78f5e1d0e70d786d686c018594e2c50bc3006b02bf80e42b2cc6a6e4b90a2c6ec5006c01f0a2cabb0bc6006c0196bdb4e904716b0c93a7e09d021dd881c9c4032ad69ce79d0a2b82ffcfaa0c329e9598a00d359dfa94a40d3ae3c3c5990e3eb1a5aea10ec100f5d9d7a50ec200fad5ddf40ec400db9cebf70ec700d6f4c7ff0fc8006ec9006b0c9b9cd0a40105bab5f1a40106918bacf10208fc9fc683050dc6b3bb9106158db2d592091698a5d0c7091791b2fab80a18e0f8fffd0b198bf3afac0d1e89b8b3b30e1fa3f3c0ad0f256ecb006c03dbb70101cbe2b58b08cc00f1bb8b880d2901cd000100c8c056ea395dd50104010200006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b172cf977b81dda406b6d6574686f645f6e616d656d6d616e6167655f6e6575726f6e6c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign(path, txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_auto_stake_maturity_candid`)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')
    } finally {
      sim.dumpEvents()
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('sign normal -- increase dissolving delay candid', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
        'd9d9f7a167636f6e74656e74a6636172675903e94449444c4e6c01dbb701786e006e796e686e786c03bc949d820302dbe2be950903ef9999fe09046c01b9ef938008786d006c02afa3bda10175c2cee0d80c076c006c029cb1fa2503ba89e5c204786b039ef5cc0f099992ccd0010adae1c99903786e0b6c01d7ab010c6c01f6b0989a08036c018eddc3a60d036c01d0e1e9f60c7e6c018dc3b2b303796c01c88ecad50a786b0996a7f7150ef381d4ab020f8cb2f18c0710b09b9ba40709d0fb87af070990f29afe0711e4ac938d0c09f7aacfd80d09c3a2f6c90e126e136c01a78882820a146c02ea99cff20475b2b8d4960b016c01c38fbbd10b016c05f5bbe3900178d2bbf0d9017eb9ef93800878dbe2be950903ef9999fe09786c04efd6e4027198abec81011ab6f798b201ca00a696a48708716e716c02cbe4fdc70471fc91f4f8051a6e1b6c02dbb70101bac7a7fa0d1c6c01bbb4b09703026c01b99d9da50b796d7b6c01cedfa0a804206e216c01e0a9b302786e236c02a9ddf49b0722d8a38ca80d246b0c9b9cd0a40105bab5f1a40106918bacf10208fc9fc683050dc6b3bb9106158db2d592091698a5d0c7091791b2fab80a18e0f8fffd0b198bf3afac0d1e89b8b3b30e1fa3f3c0ad0f256e266b02cd8e8eb90420cebee1d308006e286c03dbb70101cbe2b58b0827f1bb8b880d296c02e4d7bee905758effd6e90e206c02dbb701039df1afe707226e2c6c01f5bbe39001786c01a9ddf49b07226b02fdf59aec0b2ee3b586ff0c2f6e306c03ce9ca6ce012df382ccb30731b9ef938008786c07fed391bd0178dcd0a0ab0378dfbcb4d80478edc6ecab087993e5e481097890b090af0e78ca9ab7d20f786e336c03d889bea60d04b5f6f9e90e03c6f6ebeb0e346c02f9889a5778b2cc99e705786e366c01edbb85f901376e386c02cfbe93a40439c796cdbe0b036c01c2cee0d80c076c020075013b6d3c6c0184aead333d6e7e6d326c02f8b9b6c9043fa4ccf7dd0ac0006c089eb493cf0378befa8dd40479be8fe6e30478ce89be97067886f998bc0978c5cae3d40a7893a190e00c78f5e1d0e70d786d686c018594e2c50bc3006b02bf80e42b2cc6a6e4b90a2c6ec5006c01f0a2cabb0bc6006c0196bdb4e904716b0c93a7e09d021dd881c9c4032ad69ce79d0a2b82ffcfaa0c329e9598a00d359dfa94a40d3ae3c3c5990e3eb1a5aea10ec100f5d9d7a50ec200fad5ddf40ec400db9cebf70ec700d6f4c7ff0fc8006ec9006b0c9b9cd0a40105bab5f1a40106918bacf10208fc9fc683050dc6b3bb9106158db2d592091698a5d0c7091791b2fab80a18e0f8fffd0b198bf3afac0d1e89b8b3b30e1fa3f3c0ad0f256ecb006c03dbb70101cbe2b58b08cc00f1bb8b880d2901cd000100406c4830c8a17a0104010500ea2400006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b172e7bf51d9c01c06b6d6574686f645f6e616d656d6d616e6167655f6e6575726f6e6c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign(path, txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-sign_increase_dissolving_delay_candid`)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')
    } finally {
      sim.dumpEvents()
      await sim.close()
    }
  })

  test.concurrent.each(DEVICE_MODELS)('spawn neuron candid-protobuf invalid transactions', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
        'd9d9f7a167636f6e74656e74a76361726750620a10bcc7f5c8a3f293fb47220218326b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b172e706d8c61d2806b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f7062656e6f6e63655000000184eb5a7ffab5d56eb72b8a04df6c726571756573745f747970656463616c6c6673656e646572581df1305df1b074e88adb99dc2f56f12d63208165f24dea7e60ae6cf6cf02'

      const txBlob = Buffer.from(txBlobStr, 'hex')

      const signatureResponse = await app.sign(path, txBlob, SIGN_VALUES_P2.DEFAULT)
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x6984)
      expect(signatureResponse.errorMessage).toEqual('Data is invalid : Unexpected value')
    } finally {
      sim.dumpEvents()
      await sim.close()
    }
  })
})
