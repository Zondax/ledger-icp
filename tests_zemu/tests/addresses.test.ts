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
import { DEFAULT_OPTIONS, DEVICE_MODELS } from './common'

jest.setTimeout(180000)

const TEST_CASES = [
  {
    seed: 'drip bus mind armor hole ice glory manage speed busy hobby cup',
    prinipal: 'wcrs6-xaqh2-777q4-d2fy5-mftua-yneth-crwql-4ctbg-bsnq3-usujm-hae',
    address: '79cdf6af4c790a4d1b013ba7b301cfd2d6e3a3a0f5533da4b013850902a5a292',
  },
  {
    seed: 'donor sketch spider lunch expect maze bid cable glow shrug heart proud',
    prinipal: 'ca4dg-cmzb5-iqs7q-5mjmv-opljf-l7xup-yd75d-npqel-rgsgf-dglzt-yae',
    address: 'd2e5f3841025def4783c990bf209235699f823ec3959ed54ae6e871d8889a213',
  },
  {
    seed: 'hard deal aim medal nation chunk earn vital strong ritual brave glory',
    prinipal: 'ebrm6-pnhgu-mdv6c-hcoyf-2w4sd-orpqw-m5mxs-lfifv-iunaf-me3s2-cae',
    address: 'ceb6c721f0b805986af3f8705af7d48ec1070bfec09deb76b3040e54173606c7',
  },
  {
    seed: 'stove rival brother tuna lab sample suggest spend turtle camp shine unique',
    prinipal: 'zr3yz-g22dq-ehyjt-df2gr-c5b3b-ohxkv-gs2nf-3vxxs-bgnta-5a7h3-uae',
    address: '6b7c45475fb87912b495d902cdccaded20784d82e45d28e5ecaa3f889d816c98',
  },
]

const TEST_CASES_BIP32 = [
  {
    path: "m/44'/223'/0'/0/0",
    valid: true,
  },
  {
    path: "m/44'/223'/255'/0/0",
    valid: true,
  },
  {
    path: "m/44'/223'/0'/0/255",
    valid: true,
  },
  {
    path: "m/44'/223'/256'/0/0",
    valid: false,
  },
  {
    path: "m/44'/223'/0'/1/0",
    valid: false,
  },
  {
    path: "m/44'/223'/0'/0/256",
    valid: false,
  },
]

describe('Addresses', function () {
  test.concurrent.each(DEVICE_MODELS)('get address with seed', async function (m) {
    const sim = new Zemu(m.path)

    for (const TEST of TEST_CASES) {
      const defaultOptions_withseed = {
        ...DEFAULT_OPTIONS,
        custom: `-s "${TEST.seed}"`,
      }

      try {
        await sim.start({ ...defaultOptions_withseed, model: m.name, startText: m.name === 'stax' ? '' : 'Computer' })
        const app = new InternetComputerApp(sim.getTransport())

        const resp = await app.getAddressAndPubKey("m/44'/223'/0'/0/0")

        console.log(resp)

        expect(resp.returnCode).toEqual(0x9000)
        expect(resp.errorMessage).toEqual('No errors')

        expect(resp.principalText).toEqual(TEST.prinipal)
        expect((resp.address ?? []).toString('hex')).toEqual(TEST.address)
      } finally {
        await sim.close()
      }
    }
  })

  test.concurrent.each(DEVICE_MODELS)('derivation paths', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name, startText: m.name === 'stax' ? '' : 'Computer' })
      const app = new InternetComputerApp(sim.getTransport())

      for (const TEST of TEST_CASES_BIP32) {
        const resp = await app.getAddressAndPubKey(TEST.path)
        console.log(resp)
        const expected_returncode = TEST.valid ? 0x9000 : 0x6984
        expect(resp.returnCode).toEqual(expected_returncode)
      }
      // Enable expert mode
      console.log('Set expert mode')
      await sim.toggleExpertMode()

      for (const TEST of TEST_CASES_BIP32) {
        const resp = await app.getAddressAndPubKey(TEST.path)
        console.log(resp)
        expect(resp.returnCode).toEqual(0x9000)
      }
    } finally {
      await sim.close()
    }
  })
})
