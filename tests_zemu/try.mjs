import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import ledger_logs from '@ledgerhq/logs'
import AvalancheApp from '@zondax/ledger-icp'

const APP_DERIVATION = "m/44'/223'/0'/0/0"

async function get_icp_address(app) {
  // const resp = await app.getAddressAndPubKey(APP_DERIVATION, true)
  const resp = await app.getAddressAndPubKey(APP_DERIVATION)

  console.log(resp)
}

async function main() {
  const transport = await TransportNodeHid.default.open()
  ledger_logs.listen(log => {
    console.log(`${log.type} ${log.message}`)
  })
  const app = new AvalancheApp.default(transport)

  console.time('get_icp_address Duration')
  const resp = await get_icp_address(app)
  console.timeEnd('get_icp_address Duration')
  console.log(resp)
}

;(async () => {
  await main()
})()
