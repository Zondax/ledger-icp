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
import { DEFAULT_OPTIONS, DEVICE_MODELS_BLS } from './common'

jest.setTimeout(180000)

describe('Bls', function () {
  test.concurrent.each(DEVICE_MODELS_BLS)('verify_with_default_key', async function (m) {
    const sim = new Zemu(m.path)
    try {
      await sim.start({ ...DEFAULT_OPTIONS, model: m.name, startText: m.name === 'stax' ? '' : 'Computer' })
      const app = new InternetComputerApp(sim.getTransport())

      let consent_request =
        'd9d9f7a167636f6e74656e74a76361726758d84449444c086d7b6e766c02aeaeb1cc0501d880c6d007716c02cbaeb581017ab183e7f1077a6b028beabfc2067f8ef1c1ee0d036e046c02efcee7800402c4fbf2db05056c03d6fca70200e1edeb4a7184f7fee80a060107684449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a00000000000000070101000d69637263325f617070726f76650002656e0101230003006b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b180dfaf93de928006b6d6574686f645f6e616d6578246963726332315f63616e69737465725f63616c6c5f636f6e73656e745f6d657373616765656e6f6e636550b70f2ce7f8f414041610c3d3d4eab6d06c726571756573745f747970656463616c6c6673656e6465724104'
      let canister_call =
        'd9d9f7a167636f6e74656e74a76361726758684449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a00000000000000070101006b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b180dfaf93de928006b6d6574686f645f6e616d656d69637263325f617070726f7665656e6f6e63655007726649d5ee68e7bd09c853a5dac0fc6c726571756573745f747970656463616c6c6673656e646572581d052c5f6f270fc4a3a882a8075732cba90ad4bd25d30bd2cf7b0bfe7c02'
      let certificate =
        'd9d9f7a264747265658301830182045820f7ce39e353276ef7eac40214d6294a53d45c840988b3ad8d0655230bac1893d483018204582045c8d9bed81048bbe60926bf8585350ba6bbe6523d6f5f994fff922edbdef96e83024e726571756573745f737461747573830183018301820458202d1afceef6681d8b8a48dbc7dcde236ad09ff53487b5f65c86f402c4019c81e08301830183018301830182045820bda400ec9debeeaf0e8e4dc6308cf1d0ccc2f6861984ffe8cb5c0f7ddd006bdd830183018301830182045820c3a04b54583072b58beab029efcbd9d9f2191c061fda4c79dfcd554f57534b598302582034a44c265c7ff6c8e4ed5c3d442f12b8b52580f800ffb892a89ad56b3167a62683018302457265706c7982035903304449444c0c6b02bc8a0101c5fed201096c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b02d9e5b0980405fcdfd79a0f716c01c4d6b4ea0b066d076c01ffbb87a807086d716b04d1c4987c0aa3f2efe6020b9a8597e6030be3c581900f0b6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e0007031e2320417574686f72697a6520616e6f74686572206164647265737320746f2077697468647261772066726f6d20796f7572206163636f756e74202a2a5468651f666f6c6c6f77696e67206164647265737320697320616c6c6f77656420746f031d77697468647261772066726f6d20796f7572206163636f756e743a2a2a2272646d78362d6a616161612d61616161612d61616164712d636169202a2a596f75720d7375626163636f756e743a2a2a032330303030303030303030303030303030303030303030303030303030303030303030301d3030303030303030303030303030303030303030303030303030303030232a2a526571756573746564207769746864726177616c20616c6c6f77616e63653a2a2a032031302049435020e29aa02054686520616c6c6f77616e63652077696c6c2062652273657420746f2031302049435020696e646570656e64656e746c79206f6620616e791e70726576696f757320616c6c6f77616e63652e20556e74696c207468697303217472616e73616374696f6e20686173206265656e206578656375746564207468651e7370656e6465722063616e207374696c6c206578657263697365207468652370726576696f757320616c6c6f77616e63652028696620616e792920746f2069742773032166756c6c20616d6f756e742e202a2a45787069726174696f6e20646174653a2a2a204e6f2065787069726174696f6e2e202a2a417070726f76616c206665653a2a2a23302e3030303120494350202a2a5472616e73616374696f6e206665657320746f206265031a7061696420627920796f7572207375626163636f756e743a2a2a2330303030303030303030303030303030303030303030303030303030303030303030301d30303030303030303030303030303030303030303030303030303030308302467374617475738203477265706c696564820458205c1a351ac2b7a24b96afcaf767521613b4fd3e577aee74769266cf9f36637d4e8204582068041707ea8d374da007bb1a7a0e0bed07ab24f04b026f7986fc2a85a8fe126282045820b1dcc25b9e681479a3a0c8e48f7ec659cba3a8d2432d9da3539993e3d07ca1be820458200a9b91be81767b301772430b1e4e3347c17b107de0fd585c88108d613550f1758204582035d8238a10e9bb5c4181e35da06ebebba1aea87bb3d144b2dda13c9fcba042f4820458205f41f1b3eda637ed957dbb173be06810a3518eeca57efee3538fbded7a146ef182045820642f92e0236f3dfa2becc643a3aa9703aa4c998360b67d57b03961fdf6c704fe82045820a2092115cfa051b579b9e20a04a9d711fe65e960e47a883a7971ae348af2100282045820175aaba4eea75ae431612394d2dc78fe5058c846466011f311b90b3b5df77000830182045820bc995b4159ff52ed2d587118a4260a039b6141b7af942d7f482c34b37d62e53c83024474696d65820349c18af7abc1d9fe8618697369676e61747572655830a272688e94dffcee62a658d41a6c19cf5f531bc5d1f238ffea80706fc8ffa878cb760a68bf32fa596c651652d2e00a2a'

      const respCert = app.signBls("m/44'/223'/0'/0/0", consent_request, canister_call, certificate)

      // Wait until we are not in the main menu
      await sim.waitUntilScreenIsNot(sim.getMainMenuSnapshot())

      await sim.compareSnapshotsAndApprove('.', `${m.prefix.toLowerCase()}-bls-cert_default_key`)

      const signatureResponse = await respCert
      console.log(respCert)

      expect(signatureResponse.returnCode).toEqual(0x9000)
      expect(signatureResponse.errorMessage).toEqual('No errors')
    } finally {
      await sim.close()
    }
  })
})
