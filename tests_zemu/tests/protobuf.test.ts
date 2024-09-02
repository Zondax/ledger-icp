/**
 *******************************************************************************
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
 *******************************************************************************
 */

import InternetComputerApp, { SIGN_VALUES_P2 } from '@zondax/ledger-icp'
import Zemu from '@zondax/zemu'
import { sha256 } from 'js-sha256'
import * as secp256k1 from 'secp256k1'

import { DEFAULT_OPTIONS, DEVICE_MODELS } from './common'

jest.setTimeout(180000)

const path = "m/44'/223'/0'/0/0"
const PB_TXNS = [
  {
    name: 'pb_check_status',
    blob: 'd9d9f7a167636f6e74656e74a46e696e67726573735f6578706972791b16792e73143c0b0065706174687381824e726571756573745f7374617475735820a740262068c4b22efed0cc67095fc9ce46c883182c09aa045b4c0396060105d26c726571756573745f747970656a726561645f73746174656673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
  },
  {
    name: 'pb_increase_dissolve_delay',
    blob: 'd9d9f7a367636f6e74656e74a76c726571756573745f747970656463616c6c656e6f6e636550732123f52b79b4a4de9b89e0cc3de7586e696e67726573735f6578706972791b1674db8a3bb843006673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e3026b63616e69737465725f69644a000000000000000101016b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f7062636172674c0a02107b12060a040880a3056d73656e6465725f7075626b657958583056301006072a8648ce3d020106052b8104000a03420004e1142e1fbc940344d9161709196bb8bd151f94379c48dd507ab99a0776109128b94b5303cf2b2d28e25a779da175b62f8a975599b20c63d5193202640576ec5e6a73656e6465725f7369675840953620923534b8840d057341bfaf4511dfa73f57372e7946aed83bfde737e44c5c3005b6f19d4342b9e46c78b2c6fa4f67cf203d6a7cab51a84aa486b459536b',
  },
  {
    name: 'pb_add_hotkey',
    blob: 'd9d9f7a167636f6e74656e74a6636172675832620b10b98488e0c7a8cec9bd01122322210a1f0a1d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e3026b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b1698b4cd1475e3c06b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
  },
  {
    name: 'pb_remove_hotkey',
    blob: 'd9d9f7a167636f6e74656e74a6636172675832620b10b98488e0c7a8cec9bd0112232a210a1f0a1d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e3026b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b1698b5366ada7f006b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
  },
  {
    name: 'pb_start_dissolve',
    blob: 'd9d9f7a167636f6e74656e74a66361726751620b10e387b497ee96e3a8f201120212006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b1698b7b6ae33de406b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
  },
  {
    name: 'pb_stop_dissolve',
    blob: 'd9d9f7a167636f6e74656e74a66361726751620b10e387b497ee96e3a8f20112021a006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b1698b7bc219b61006b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
  },
  {
    name: 'pb_disburse',
    blob: 'd9d9f7a167636f6e74656e74a6636172675839620a10a7d18aaad3a2a2c6131a2b0a0508959aef3a12220a2068d518e2fd2be6566e62c36611b9794dfcbc04eb4227eefb73ab3c7a2d0ae5776b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b169bc8985c330d006b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
  },
  {
    name: 'pb_list_neurons',
    blob: 'd9d9f7a167636f6e74656e74a6636172674210016b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b169bc0d5904b7e806b6d6574686f645f6e616d656f6c6973745f6e6575726f6e735f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
  },
  {
    name: 'pb_spawn_neuron',
    blob: 'd9d9f7a167636f6e74656e74a6636172674f620b10f5c88584a9f98ded910122006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b169bc108342f99006b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
  },
  {
    name: 'pb_register_vote',
    blob: 'd9d9f7a167636f6e74656e74a6636172674d620310c8033a060a02087b10016b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16abc427b2b658406b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
  },
  {
    name: 'pb_follow',
    blob: 'd9d9f7a167636f6e74656e74a663617267546202107b2a0e120310c80312031095061202107b6b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16abfff247c1f9c06b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
  },
  {
    name: 'pb_claim_neurons',
    blob: 'd9d9f7a167636f6e74656e74a76c726571756573745f747970656463616c6c656e6f6e6365505833a6590c6d2b601e3a24557cfbb4336e696e67726573735f6578706972791b16bad506bb4ca0f06673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e3026b63616e69737465725f69644a000000000000000601016b6d6574686f645f6e616d656d636c61696d5f6e6575726f6e7363617267588b4449444c000171820130343139623066656363356639613164353162393033643262363234346430356531326134386661386233353731396538313262623635643966393035613365613965356137323362363537616665393136313236396431663134633164383034376530323230616461633434653731313630323531656364616662613064636535',
  },
  {
    name: 'pb_join_community_fund',
    blob: 'd9d9f7a167636f6e74656e74a663617267486202107b12023a006b63616e69737465725f69644a000000000000000101016e696e67726573735f6578706972791b16ba67d2b864bf406b6d6574686f645f6e616d65706d616e6167655f6e6575726f6e5f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
  },
]

describe.each(PB_TXNS)('PROTOBUF TRANSACTIONS', function (data) {
  test.concurrent.each(DEVICE_MODELS)(`Test: ${data.name}`, async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name, startText: m.name === 'stax' ? '' : 'Computer' })
      const app = new InternetComputerApp(sim.getTransport())

      const respAddr = await app.getAddressAndPubKey(path)

      const txBlob = Buffer.from(data.blob, 'hex')

      const respRequest = app.sign(path, txBlob, SIGN_VALUES_P2.DEFAULT)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-${data.name}`)

      const signatureResponse = await respRequest
      console.log(signatureResponse)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')

      // Verify signature
      const hash = sha256.hex(signatureResponse.preSignHash ?? [])

      const hexPubkey = respAddr.publicKey ?? Buffer.alloc(0)
      const pk = Uint8Array.from(hexPubkey)
      expect(pk.byteLength).toEqual(65)

      const digest = Uint8Array.from(Buffer.from(hash, 'hex'))
      const signature = Uint8Array.from(signatureResponse.signatureRS ?? [])
      expect(signature.byteLength).toEqual(64)

      const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk)
      expect(signatureOk).toEqual(true)
    } finally {
      await sim.close()
    }
  })
})

test.concurrent.each(DEVICE_MODELS)(`protobuf stake_neuron`, async function (m) {
  const sim = new Zemu(m.path)
  try {
    await sim.start({ ...DEFAULT_OPTIONS, model: m.name, startText: m.name === 'stax' ? '' : 'Computer' })
    const app = new InternetComputerApp(sim.getTransport())

    const respAddr = await app.getAddressAndPubKey(path)

    const txBlob = Buffer.from(
      'd9d9f7a167636f6e74656e74a663617267583e0a0a08f2d4a0eca697869f0812070a050880c2d72f1a0308904e2a220a20a8a1abecdb66f57eb6eba44c3b5f11a6c433fe932680a9519b064b80ca8794e16b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b16985a582755f1806b6d6574686f645f6e616d656773656e645f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302',
      'hex',
    )

    const respRequest = app.sign(path, txBlob, SIGN_VALUES_P2.STAKE_TX)

    // Wait until we are not in the main menu
    await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

    await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-pb_stake_neuron`)

    const signatureResponse = await respRequest
    console.log(signatureResponse)

    expect(signatureResponse.returnCode).toEqual(0x9000)
    expect(signatureResponse.errorMessage).toEqual('No errors')

    // Verify signature
    const hash = sha256.hex(signatureResponse.preSignHash ?? [])

    const hexPubkey = respAddr.publicKey ?? Buffer.alloc(0)
    const pk = Uint8Array.from(hexPubkey)
    expect(pk.byteLength).toEqual(65)

    const digest = Uint8Array.from(Buffer.from(hash, 'hex'))
    const signature = Uint8Array.from(signatureResponse.signatureRS ?? [])
    expect(signature.byteLength).toEqual(64)

    const signatureOk = secp256k1.ecdsaVerify(signature, digest, pk)
    expect(signatureOk).toEqual(true)
  } finally {
    await sim.close()
  }
})

test.concurrent.each(DEVICE_MODELS)('sign combined_tx', async function (m) {
  const sim = new Zemu(m.path)
  try {
    await sim.start({ ...DEFAULT_OPTIONS, model: m.name, startText: m.name === 'stax' ? '' : 'Computer' })
    const app = new InternetComputerApp(sim.getTransport())

    const txBlobStr_read =
      'd9d9f7a167636f6e74656e74a46e696e67726573735f6578706972791b16bc685267142b8065706174687381824e726571756573745f73746174757358208d304d294d3f611f992b3f2b184d32b9b3c058d918d7a7ab1946614b13ba0a496c726571756573745f747970656a726561645f73746174656673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
    const txBlob_read = Buffer.from(txBlobStr_read, 'hex')

    const txBlobStr_request =
      'd9d9f7a167636f6e74656e74a66361726758320a0012050a0308904e1a0308904e2a220a20a2a794c66495083317e4be5197eb655b1e63015469d769e2338af3d3e3f3aa866b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b16bc685084d14ec06b6d6574686f645f6e616d656773656e645f70626c726571756573745f747970656463616c6c6673656e646572581d19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
    const txBlob_request = Buffer.from(txBlobStr_request, 'hex')

    const respRequest = app.signUpdateCall("m/44'/223'/0'/0/0", txBlob_request, txBlob_read, SIGN_VALUES_P2.DEFAULT)

    // Wait until we are not in the main menu
    await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

    await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-pb_sign_update_call`)

    const signatureResponse = await respRequest
    console.log(signatureResponse)

    expect(signatureResponse.returnCode).toEqual(0x9000)
    expect(signatureResponse.errorMessage).toEqual('No errors')

    const pk = Uint8Array.from(
      Buffer.from(
        '0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835',
        'hex',
      ),
    )

    const digest_request = Uint8Array.from(signatureResponse.RequestHash ?? [])
    const signature_request = Uint8Array.from(signatureResponse.RequestSignatureRS ?? [])
    expect(signature_request.byteLength).toEqual(64)

    const signatureOk = secp256k1.ecdsaVerify(signature_request, digest_request, pk)
    expect(signatureOk).toEqual(true)

    const digest_statusread = Uint8Array.from(signatureResponse.StatusReadHash ?? [])
    const signature_statusread = Uint8Array.from(signatureResponse.StatusReadSignatureRS ?? [])
    expect(signature_request.byteLength).toEqual(64)

    const signatureOk_statusread = secp256k1.ecdsaVerify(signature_statusread, digest_statusread, pk)
    expect(signatureOk_statusread).toEqual(true)
  } finally {
    await sim.close()
  }
})
