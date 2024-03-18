import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import ledger_logs from '@ledgerhq/logs'
import InternetComputerApp from '@zondax/ledger-icp'

async function main() {
  const transport = await TransportNodeHid.default.open()
  ledger_logs.listen(log => {
    console.log(`${log.type} ${log.message}`)
  })

  const app = new InternetComputerApp(sim.getTransport())
  const respRequest = app.showAddressAndPubKey("m/44'/223'/0'/0/0")
  const resp = await respRequest
  console.log(resp)
}

;(async () => {
  await main()
})()

