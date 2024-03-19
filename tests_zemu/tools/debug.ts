import { DEFAULT_START_OPTIONS, IDeviceModel, IStartOptions } from '@zondax/zemu'
import Zemu, { ButtonKind, zondaxMainmenuNavigation } from '@zondax/zemu'

import TransportNodeHid from '@ledgerhq/hw-transport-node-hid'
import ledger_logs from '@ledgerhq/logs'
import InternetComputerApp from '@zondax/ledger-icp'

import { resolve } from 'path'

const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

const DEFAULT_OPTIONS = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
}

const APP_PATH_S = resolve('../../app/output/app_s.elf')
const APP_PATH_X = resolve('../../app/output/app_x.elf')
const APP_PATH_SP = resolve('../../app/output/app_s2.elf')
const APP_PATH_ST = resolve('../../app/output/app_stax.elf')

const models = { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP }
// const models = { name: 'nanos', prefix: 'S', path: APP_PATH_S }

async function main() {
  console.log('path: ', models)
  const sim = new Zemu(models.path)

  try {
    await sim.start({
      ...DEFAULT_OPTIONS,
      startText: models.name === 'stax' ? '' : 'Computer',
      approveKeyword: models.name === 'stax' ? 'Principal' : '',
      approveAction: ButtonKind.ApproveTapButton,
    })

    const app = new InternetComputerApp(sim.getTransport())
    await sim.toggleExpertMode()

    const resp = await app.getAddressAndPubKey("m/44'/223'/0'/0/0")

    console.log(resp)
  } catch (error) {
    // Handle any errors that occurred during the try block
    console.error('An error occurred:', error)
  } finally {
    console.log('Cleaning up, if necessary')
  }
}

;(async () => {
  await main()
})()
