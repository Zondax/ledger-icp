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

const APP_PATH_S = resolve('../app/output/app_s.elf')
const APP_PATH_X = resolve('../app/output/app_x.elf')
const APP_PATH_SP = resolve('../../app/bin/app.elf')
const APP_PATH_ST = resolve('../app/output/app_stax.elf')

const models: IDeviceModel[] = [
  // { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  // { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  // { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
]

async function main() {
  // const sim = new Zemu(m.path)
  const sim = new Zemu(models[0].path)

  try {
    await sim.start({
      ...DEFAULT_OPTIONS,
      startText: models[0].name === 'stax' ? '' : 'Computer',
      approveKeyword: models[0].name === 'stax' ? 'Principal' : '',
      approveAction: ButtonKind.ApproveTapButton,
    })

    const app = new InternetComputerApp(sim.getTransport())
    await sim.toggleExpertMode()

    const resp = await app.getAddressAndPubKey("m/44'/223'/0'/0/0")

    const resp = await respRequest

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
