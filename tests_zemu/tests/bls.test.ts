/** ******************************************************************************
 *  (c) 2020 Zondax AG
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

import Zemu, { ButtonKind, ClickNavigation, TouchNavigation } from '@zondax/zemu'
import InternetComputerApp from '@zondax/ledger-icp'
import { DEFAULT_OPTIONS, DEVICE_MODELS_BLS } from './common'
import { TEST_DATA } from './bls_test_data'

jest.setTimeout(180000)

const PRIMARY_PATH = "m/44'/223'/0'/0/0"
const ALTERNATE_PATH = "m/44'/223'/1'/0/0"

describe('Bls', function () {
  test.each(DEVICE_MODELS_BLS)('verify_with_default_key', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name, startText: m.name === 'stax' ? '' : 'Computer' })
      const app = new InternetComputerApp(sim.getTransport())

      const respCert = app.signBls(PRIMARY_PATH, TEST_DATA.CONSENT_REQUEST, TEST_DATA.CANISTER_CALL, TEST_DATA.CERTIFICATE)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-bls-cert_default_key`, true, 0, 15000)

      const signatureResponse = await respCert
      console.log(respCert)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })

  test.each(DEVICE_MODELS_BLS)('rejects derivation path switches before review', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name, startText: m.name === 'stax' ? '' : 'Computer' })
      const app = new InternetComputerApp(sim.getTransport())

      const consent = await app.sendData(PRIMARY_PATH, TEST_DATA.CONSENT_REQUEST, app.INS.SAVE_CONSENT)
      expect(consent.returnCode).toEqual(0x9000)

      const switchedCall = await app.sendData(ALTERNATE_PATH, TEST_DATA.CANISTER_CALL, app.INS.SAVE_CANISTER_CALL)
      expect(switchedCall.returnCode).toEqual(0x6984)

      const restartedConsent = await app.sendData(PRIMARY_PATH, TEST_DATA.CONSENT_REQUEST, app.INS.SAVE_CONSENT)
      expect(restartedConsent.returnCode).toEqual(0x9000)

      const matchingCall = await app.sendData(PRIMARY_PATH, TEST_DATA.CANISTER_CALL, app.INS.SAVE_CANISTER_CALL)
      expect(matchingCall.returnCode).toEqual(0x9000)

      const switchedCertificate = await app.sendCertificateAndSig(ALTERNATE_PATH, TEST_DATA.CERTIFICATE)
      expect(switchedCertificate.returnCode).toEqual(0x6984)
    } finally {
      await sim.close()
    }
  })
})
