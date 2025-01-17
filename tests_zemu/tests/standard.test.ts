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

import Zemu, { ButtonKind, zondaxMainmenuNavigation, isTouchDevice } from '@zondax/zemu'
import InternetComputerApp from '@zondax/ledger-icp'
import { DEFAULT_OPTIONS, DEVICE_MODELS } from './common'

jest.setTimeout(180000)

describe('Standard', function () {
  test.each(DEVICE_MODELS)('can start and stop container', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name, startText: isTouchDevice(m.name) ? '' : 'Computer' })
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('main menu', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name, startText: isTouchDevice(m.name) ? '' : 'Computer' })
      await sim.navigateAndCompareSnapshots('.', `${m.prefix.toLowerCase()}-mainmenu`, zondaxMainmenuNavigation(m.name).schedule)
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('get app version', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name, startText: isTouchDevice(m.name) ? '' : 'Computer' })
      const app = new InternetComputerApp(sim.getTransport())
      const resp = await app.getVersion()

      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')
      expect(resp).toHaveProperty('testMode')
      expect(resp).toHaveProperty('major')
      expect(resp).toHaveProperty('minor')
      expect(resp).toHaveProperty('patch')
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('get address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name, startText: isTouchDevice(m.name) ? '' : 'Computer' })
      const app = new InternetComputerApp(sim.getTransport())

      const resp = await app.getAddressAndPubKey("m/44'/223'/0'/0/0")

      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')

      const expected_principalTextual = '5upke-tazvi-6ufqc-i3v6r-j4gpu-dpwti-obhal-yb5xj-ue32x-ktkql-rqe'
      const expected_principal = '19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const expected_pk =
        '0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835'
      const expected_address = '4f3d4b40cdb852732601fccf8bd24dffe44957a647cb867913e982d98cf85676'

      expect((resp.principal ?? []).toString('hex')).toEqual(expected_principal)
      expect(resp.principalText).toEqual(expected_principalTextual)
      expect((resp.publicKey ?? []).toString('hex')).toEqual(expected_pk)
      expect((resp.address ?? []).toString('hex')).toEqual(expected_address)
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('show address', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...DEFAULT_OPTIONS,
        model: m.name,
        startText: isTouchDevice(m.name) ? '' : 'Computer',
        approveKeyword: isTouchDevice(m.name) ? 'Principal' : '',
        approveAction: ButtonKind.ApproveTapButton,
      })
      const app = new InternetComputerApp(sim.getTransport())

      await sim.toggleExpertMode()

      const respRequest = app.showAddressAndPubKey("m/44'/223'/0'/0/0")

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-show_address`)

      const resp = await respRequest

      console.log(resp)

      expect(resp.returnCode).toEqual(0x9000)
      expect(resp.errorMessage).toEqual('No errors')

      const expected_principalTextual = '5upke-tazvi-6ufqc-i3v6r-j4gpu-dpwti-obhal-yb5xj-ue32x-ktkql-rqe'
      const expected_principal = '19aa3d42c048dd7d14f0cfa0df69a1c1381780f6e9a137abaa6a82e302'
      const expected_pk =
        '0410d34980a51af89d3331ad5fa80fe30d8868ad87526460b3b3e15596ee58e812422987d8589ba61098264df5bb9c2d3ff6fe061746b4b31a44ec26636632b835'
      const expected_address = '4f3d4b40cdb852732601fccf8bd24dffe44957a647cb867913e982d98cf85676'

      expect((resp.principal ?? []).toString('hex')).toEqual(expected_principal)
      expect(resp.principalText).toEqual(expected_principalTextual)
      expect((resp.publicKey ?? []).toString('hex')).toEqual(expected_pk)
      expect((resp.address ?? []).toString('hex')).toEqual(expected_address)
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS)('show address - reject', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({
        ...DEFAULT_OPTIONS,
        model: m.name,
        startText: isTouchDevice(m.name) ? '' : 'Computer',
        rejectKeyword: isTouchDevice(m.name) ? 'Principal' : '',
      })
      const app = new InternetComputerApp(sim.getTransport())

      await sim.toggleExpertMode()

      const respRequest = app.showAddressAndPubKey("m/44'/223'/0'/0/0")

      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndReject('.', `${m.prefix.toLowerCase()}-show_address_reject`)

      const resp = await respRequest

      console.log(resp)

      expect(resp.returnCode).toEqual(0x6986)
      expect(resp.errorMessage).toEqual('Transaction rejected')
    } finally {
      await sim.close()
    }
  })
})
