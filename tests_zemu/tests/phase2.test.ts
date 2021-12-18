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

import Zemu, { DEFAULT_START_OPTIONS, DeviceModel } from '@zondax/zemu'
import InternetComputerApp from '@zondax/ledger-icp'
import * as secp256k1 from 'secp256k1'
import {SIGN_VALUES_P2} from "@zondax/ledger-icp/dist/common";

const sha256 = require('js-sha256')

const Resolve = require('path').resolve
const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/app_x.elf')

const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const defaultOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  X11: false,
}

jest.setTimeout(60000)

const models: DeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
]

beforeAll(async () => {
  await Zemu.checkAndPullImage()
})

describe('Phase2', function () {
  test.each(models)('sign normal -- Increase Neuron Timer', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const pkhex =
          '0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835'

      const txBlobStr =
          'd9d9f7a367636f6e74656e74a76c726571756573745f747970656463616c6c656e6f6e636550732123f52b79b4a4de9b89e0cc3de7586e696e67726573735f6578706972791b1674db8a3bb843006673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e3026b63616e69737465725f69644a000000000000000101016b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f7062636172674c0a02107b12060a040880a3056d73656e6465725f7075626b657958583056301006072a8648ce3d020106052b8104000a03420004e1142e1fbc940344d9161709196bb8bd151f94379c48dd507ab99a0776109128b94b5303cf2b2d28e25a779da175b62f8a975599b20c63d5193202640576ec5e6a73656e6465725f7369675840953620923534b8840d057341bfaf4511dfa73f57372e7946aed83bfde737e44c5c3005b6f19d4342b9e46c78b2c6fa4f67cf203d6a7cab51a84aa486b459536b'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_increaseTimer_normal`, m.name === 'nanos' ? 3 : 4)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

      const hash = sha256.hex(signatureResponse.preSignHash)

      const pk = Uint8Array.from(Buffer.from(pkhex, 'hex'))
      expect(pk.byteLength).toEqual(65)
      const digest = Uint8Array.from(Buffer.from(hash, 'hex'))
      const signature = Uint8Array.from(signatureResponse.signatureRS)
      //const signature = secp256k1.signatureImport(Uint8Array.from(signatureResponse.signatureDER));
      expect(signature.byteLength).toEqual(64)

      const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk)
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign normal -- stake transfer', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const expected_pk =
          '0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835'

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a663617267583e0a0a08f2d4a0eca697869f0812070a050880c2d72f1a0308904e2a220a20a8a1abecdb66f57eb6eba44c3b5f11a6c433fe932680a9519b064b80ca8794e16b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b16985a582755f1806b6d6574686f645f6e616d656773656e645f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'

      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.STAKE_TX)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_staketx_normal`, m.name === 'nanos' ? 6 : 7)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

      const hash = sha256.hex(signatureResponse.preSignHash)

      const pk = Uint8Array.from(Buffer.from(expected_pk, 'hex'))
      const digest = Uint8Array.from(Buffer.from(hash, 'hex'))
      const signature = Uint8Array.from(signatureResponse.signatureRS)
      expect(signature.byteLength).toEqual(64)

      const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk)
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign normal -- add hotkey', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a6636172675832620b10b98488e0c7a8cec9bd01122322210a1f0a1d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e3026b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b1698b4cd1475e3c06b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'

      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_addHotkey`, m.name === 'nanos' ? 4 : 5)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign normal -- remove hotkey', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a6636172675832620b10b98488e0c7a8cec9bd0112232a210a1f0a1d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e3026b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b1698b5366ada7f006b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'

      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_removeHotkey`, m.name === 'nanos' ? 4 : 5)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })


  test.each(models)('sign normal -- start dissolve', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a66361726751620b10e387b497ee96e3a8f201120212006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b1698b7b6ae33de406b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'

      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_startdissolve`, m.name === 'nanos' ? 2 : 3)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign normal -- stop dissolve', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a66361726751620b10e387b497ee96e3a8f20112021a006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b1698b7bc219b61006b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'

      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_stopdissolve`, m.name === 'nanos' ? 2 : 3)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign normal -- disburse', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a6636172675839620a10a7d18aaad3a2a2c6131a2b0a0508959aef3a12220a2068d518e2fd2be6566e62c36611b9794dfcbc04eb4227eefb73ab3c7a2d0ae5776b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b169bc8985c330d006b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'

      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_disburse`, m.name === 'nanos' ? 5 : 6)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign normal -- list neurons', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a6636172674210016b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b169bc0d5904b7e806b6d6574686f645f6e616d656f6c6973745f6e6575726f6e735f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_listneurons`, m.name === 'nanos' ? 1 : 2)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign normal -- spawn', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a6636172674f620b10f5c88584a9f98ded910122006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b169bc108342f99006b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_spawn`, m.name === 'nanos' ? 3 : 4)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign normal -- Merge Mature', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a66361726748620210016a02080e6b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16abbdeb03397c406b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_MergeMature`, m.name === 'nanos' ? 3 : 4)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign normal -- Register Vote', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a6636172674d620310c8033a060a02087b10016b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16abc427b2b658406b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_RegisterVote`, m.name === 'nanos' ? 4 : 5)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })
  test.each(models)('sign normal -- follow', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a663617267546202107b2a0e120310c80312031095061202107b6b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16abfff247c1f9c06b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-sign_follow`, m.name === 'nanos' ? 6 : 7)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign normal -- claimneuron', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a76c726571756573745f747970656463616c6c656e6f6e6365505833a6590c6d2b601e3a24557cfbb4336e696e67726573735f6578706972791b16bad506bb4ca0f06673656e646572581d19AA3D42C048DD7D14F0CFA0DF69A1C1381780F6E9A137ABAA6A82E3026b63616e69737465725f69644a000000000000000601016b6d6574686f645f6e616d656d636c61696d5f6e6575726f6e7363617267588b4449444c000171820130343139623066656363356639613164353162393033643262363234346430356531326134386661386233353731396538313262623635643966393035613365613965356137323362363537616665393136313236396431663134633164383034376530323230616461633434653731313630323531656364616662613064636535'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-claim_neuron`, m.name === 'nanos' ? 1 : 2)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

  test.each(models)('sign normal -- join community fund', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...defaultOptions, model: m.name })
      const app = new InternetComputerApp(sim.getTransport())

      const txBlobStr =
          'd9d9f7a167636f6e74656e74a663617267486202107b12023a006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16ba67d2b864bf406b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19AA3D42C048DD7D14F0CFA0DF69A1C1381780F6E9A137ABAA6A82E302'
      const txBlob = Buffer.from(txBlobStr, 'hex')

      const respRequest = app.sign("m/44'/223'/0'/0/0", txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndAccept('.', `${m.prefix.toLowerCase()}-join_community_fund`, m.name === 'nanos' ? 2 : 3)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

    } finally {
      await sim.close()
    }
  })

})