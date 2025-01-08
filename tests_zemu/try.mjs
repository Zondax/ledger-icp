import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import ledger_logs from '@ledgerhq/logs'
import InternetComputerApp from '@zondax/ledger-icp'

const APP_DERIVATION = "m/44'/223'/0'/0/0"
const CERT =
  'd9d9f7a26474726565830183018204582017eaa0bbc9af4f137faf4a51cc0c4e07a18137c194acaf01ce083408a6bcd34c83018204582014d167f225d453ac197ae54777bd7b0d155796631e879d97dbb5c963c58c97f883024e726571756573745f7374617475738301830183018301830182045820517b60ab64086504f07e45e1af3b069a790741ff6f7af4c0e4b18f1b442c6e3f8301830182045820541e4d2e2d3da6cf87ebfa0b8aebe85c4f7b9275b4736b49235ddc836e1c87558301820458207f6c26797e95a077ca57c7df0912c3084f73efd9479c2425fe8044f495b80250830183018204582005cbc8f3d0ace8f69b48a0b8427641d06bd52a2f87f769f38a27e9b63bc264978301820458207f6b21dad00a46d4cc67b6389f1f24c5b5c43c093fe32c5d691505c0268c03ac8301830258201439a6ad6fc2cf5c38977fd43aef03d338378ba0082105c2b6940abfdd12740083018302457265706c79820359032d4449444c0c6b02bc8a0101c5fed201096c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b02d9e5b0980405fcdfd79a0f716c01c4d6b4ea0b066d076c01ffbb87a807086d716b04d1c4987c0aa3f2efe6020b9a8597e6030be3c581900f0b6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e01a4052320417574686f72697a6520616e6f74686572206164647265737320746f2077697468647261772066726f6d20796f7572206163636f756e740a0a2a2a54686520666f6c6c6f77696e67206164647265737320697320616c6c6f77656420746f2077697468647261772066726f6d20796f7572206163636f756e743a2a2a0a72646d78362d6a616161612d61616161612d61616164712d6361690a0a2a2a596f7572207375626163636f756e743a2a2a0a303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030300a0a2a2a526571756573746564207769746864726177616c20616c6c6f77616e63653a2a2a0a3130204943500ae29aa02054686520616c6c6f77616e63652077696c6c2062652073657420746f2031302049435020696e646570656e64656e746c79206f6620616e792070726576696f757320616c6c6f77616e63652e20556e74696c2074686973207472616e73616374696f6e20686173206265656e20657865637574656420746865207370656e6465722063616e207374696c6c206578657263697365207468652070726576696f757320616c6c6f77616e63652028696620616e792920746f20697427732066756c6c20616d6f756e742e0a0a2a2a45787069726174696f6e20646174653a2a2a0a4e6f2065787069726174696f6e2e0a0a2a2a417070726f76616c206665653a2a2a0a302e30303031204943500a0a2a2a5472616e73616374696f6e206665657320746f206265207061696420627920796f7572207375626163636f756e743a2a2a0a303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030308302467374617475738203477265706c6965648204582098a36bd5a862a11bcd8cc7fe09f6e3089d72087cf54517d8beed1561d3632a23820458202ba4a93540ff5f91efcb0b6d9ab4f8e49b817df43a6bb802d17b605d0b5bdbdf820458203317f464946391447ed1e3a43fe196ef7b341541651df2b1b575a83a483e5575820458209272b13d77b429a2d2e4937bfb9bf230e409a0f0142511295b07e5f221a08cf48204582086663d79a2b64a1b3e0c828d85a688aec84c9809807c5c9f51b7875addf22bf782045820c7ea11c586c4a88c9806c03bab35269a099ae6e5c667d819901e07e406e3675782045820cd94f63e7e6269f8f16de79c5182f585c5f0118b5458db44ee8dc7bbc5768da38301820458205484a7a8650bfca792e8ef3dd2658c361cd9e38ba77b4ecaaf7b9cccb21956d883024474696d65820349ceafef8cb6f4bd8b18697369676e61747572655830b992e9ced1b7e7c1a908598cb37888312977ef2e5868c54833dfd8ab9654120adea17614527c69ceaf19203765bcdc43'
const CALL =
  'd9d9f7a167636f6e74656e74a76361726758684449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a00000000000000070101006b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b1816f7d9847308006b6d6574686f645f6e616d656d69637263325f617070726f7665656e6f6e636550bc82f1ea7ead7e1bd0a35dcf586947f76c726571756573745f747970656463616c6c6673656e646572581d052c5f6f270fc4a3a882a8075732cba90ad4bd25d30bd2cf7b0bfe7c02'
const CONSENT =
  'd9d9f7a167636f6e74656e74a76361726758d44449444c086d7b6e766c02aeaeb1cc0501d880c6d007716c02cbaeb581017ab183e7f1077a6b028beabfc2067f8ef1c1ee0d036e046c02efcee7800402c4fbf2db05056c03d6fca70200e1edeb4a7184f7fee80a060107684449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a00000000000000070101000d69637263325f617070726f76650002656e01006b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b1816f7d9847308006b6d6574686f645f6e616d6578246963726332315f63616e69737465725f63616c6c5f636f6e73656e745f6d657373616765656e6f6e6365504ce74de6e2597a02d4f24eefd1604db06c726571756573745f747970656463616c6c6673656e6465724104'
const ROOT_KEY =
  '814c0e6ec71fab583b08bd81373c255c3c371b2e84863c98a4f1e08b74235d14fb5d9c0cd546d9685f913a0c0b2cc5341583bf4b4392e467db96d65b9bb4cb717112f8472e0d5a4d14505ffd7484b01291091c5f87b98883463f98091a0baaae'

async function bls_verify(app) {
  // const resp = await app.getAddressAndPubKey(APP_DERIVATION, true)
  let consent_request =
    'd9d9f7a167636f6e74656e74a76361726758d84449444c086d7b6e766c02aeaeb1cc0501d880c6d007716c02cbaeb581017ab183e7f1077a6b028beabfc2067f8ef1c1ee0d036e046c02efcee7800402c4fbf2db05056c03d6fca70200e1edeb4a7184f7fee80a060107684449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a00000000000000070101000d69637263325f617070726f76650002656e0101230003006b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b18150c3b3dc330006b6d6574686f645f6e616d6578246963726332315f63616e69737465725f63616c6c5f636f6e73656e745f6d657373616765656e6f6e636550b85af2a8a93d368101dfb945a4bfaa056c726571756573745f747970656463616c6c6673656e6465724104'
  let canister_call =
    'd9d9f7a167636f6e74656e74a76361726758684449444c066e7d6d7b6e016e786c02b3b0dac30368ad86ca8305026c08c6fcb60200ba89e5c20402a2de94eb060282f3f3910c03d8a38ca80d7d919c9cbf0d00dea7f7da0d03cb96dcb40e04010501904e0000008094ebdc030000010a00000000000000070101006b63616e69737465725f69644a000000000000000201016e696e67726573735f6578706972791b18150c3b3dc330006b6d6574686f645f6e616d656d69637263325f617070726f7665656e6f6e6365506dce3e5808515edca41a94e4c2a480d06c726571756573745f747970656463616c6c6673656e646572581d052c5f6f270fc4a3a882a8075732cba90ad4bd25d30bd2cf7b0bfe7c02'
  let certificate =
    'd9d9f7a264747265658301830182045820b4b214b4daf257d7313e5f029cc55c514806b73578d2c6a8b34c456062b2fcca83018204582012d3bf7eb1c51eee0b021c8eb2f545ac6b6319f6d02610f6fd8d4a4a285d8f2183024e726571756573745f73746174757383018301820458201e8ff50918e5246325a1a24856a30b2db91b8d72dbd7fd1bb7d6345dbb33d5c1830182045820a4b38b70584077412bdbf594799f6973d3cd311c8f0c5e273f6ccbcb038b4e4f8301830182045820137c7e4f8801755bd96a3542a5948a2ad1d141f44e9b60f38d49f7718bf1e03683018301820458203c8bf754339883c7525829c0e21c5234cce654869079802b8175d3bbf6e264e8830182045820abec4914cb21aea85a381d607711d638900b28d316bfafd05d18792e28437d4f8301820458205c2a68619fcfedd660383e0330525f398771b5de56e8361eb29f5d08c74e66628301830182045820b4af5a98eafab04c4f1c86b7cc2125be7be04dc92cda06eee68a2ecbd2b474cd830183025820d43ea96d58d742990b277b60875a485361efd0f80868ef8025f25239065fa8f683018302457265706c7982035903304449444c0c6b02bc8a0101c5fed201096c02efcee7800402e29fdcc806046c02aeaeb1cc0503d880c6d007716e766b02d9e5b0980405fcdfd79a0f716c01c4d6b4ea0b066d076c01ffbb87a807086d716b04d1c4987c0aa3f2efe6020b9a8597e6030be3c581900f0b6c02fc91f4f80571c498b1b50d7d6c01fc91f4f805710100000002656e0007031e2320417574686f72697a6520616e6f74686572206164647265737320746f2077697468647261772066726f6d20796f7572206163636f756e74202a2a5468651f666f6c6c6f77696e67206164647265737320697320616c6c6f77656420746f031d77697468647261772066726f6d20796f7572206163636f756e743a2a2a2272646d78362d6a616161612d61616161612d61616164712d636169202a2a596f75720d7375626163636f756e743a2a2a032330303030303030303030303030303030303030303030303030303030303030303030301d3030303030303030303030303030303030303030303030303030303030232a2a526571756573746564207769746864726177616c20616c6c6f77616e63653a2a2a032031302049435020e29aa02054686520616c6c6f77616e63652077696c6c2062652273657420746f2031302049435020696e646570656e64656e746c79206f6620616e791e70726576696f757320616c6c6f77616e63652e20556e74696c207468697303217472616e73616374696f6e20686173206265656e206578656375746564207468651e7370656e6465722063616e207374696c6c206578657263697365207468652370726576696f757320616c6c6f77616e63652028696620616e792920746f2069742773032166756c6c20616d6f756e742e202a2a45787069726174696f6e20646174653a2a2a204e6f2065787069726174696f6e2e202a2a417070726f76616c206665653a2a2a23302e3030303120494350202a2a5472616e73616374696f6e206665657320746f206265031a7061696420627920796f7572207375626163636f756e743a2a2a2330303030303030303030303030303030303030303030303030303030303030303030301d30303030303030303030303030303030303030303030303030303030308302467374617475738203477265706c696564820458201bec75e20d0c3f6021b3200774ddaf3dc8a110f205a09e82e0d7b9d24363998382045820d1c75859aefa34353f19e442a1ea39108ccdf1bb63dd92fa5972e402f9d9b1a682045820d9ded99e671ff3a6b57e4163682f3230f5c4c71feba54cac754463dc639a6fa182045820807cc02385aa89ff4100c9d8074746ad71ae0eea3bd0cfadda4695f2ba9b0f9e8204582075160808a4dafab7a6b818fd73475daf0888aaa80dc1634910bc3d15cc882503830182045820cfa7e97fa9ab19a491938689465bf33142082e4d95061b6e1ce4e865a6571cf383024474696d65820349cafdf2acc980c38a18697369676e61747572655830b40e48a11d3c82b199e694276f5e7128f5a82ff1ecff3cab388bdeaea8a97300ac02334967b27c47a3c3d7ed323482b3'

  // const resp = await app.signBls(APP_DERIVATION, consent_request, canister_call, certificate)
  const resp = await app.signBls(APP_DERIVATION, CONSENT, CALL, CERT)

  console.log(resp)
}

async function main() {
  const transport = await TransportNodeHid.default.open()
  ledger_logs.listen(log => {
    console.log(`${log.type} ${log.message}`)
  })
  const app = new InternetComputerApp(transport)

  console.time('bls_verify Duration')
  const resp = await bls_verify(app)
  console.timeEnd('bls_verify Duration')
  console.log(resp)
}

;(async () => {
  await main()
})()
