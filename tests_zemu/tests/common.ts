import { DEFAULT_START_OPTIONS, IDeviceModel, IStartOptions } from '@zondax/zemu'
import { resolve } from 'path'

const APP_PATH_X = resolve('../app/output/app_x.elf')
const APP_PATH_SP = resolve('../app/output/app_s2.elf')
const APP_PATH_ST = resolve('../app/output/app_stax.elf')
const APP_PATH_FL = resolve('../app/output/app_flex.elf')
const APP_PATH_AP = resolve('../app/output/app_apex_p.elf')

const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

export const DEFAULT_OPTIONS: IStartOptions = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
}

export const DEVICE_MODELS: IDeviceModel[] = [
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
  { name: 'flex', prefix: 'FL', path: APP_PATH_FL },
  { name: "apex_p", prefix: "AP", path: APP_PATH_AP },
]

export const DEVICE_MODELS_BLS: IDeviceModel[] = [
  // { name: 'nanox', prefix: 'X', path: APP_PATH_X },
  { name: 'nanosp', prefix: 'SP', path: APP_PATH_SP },
  { name: 'stax', prefix: 'ST', path: APP_PATH_ST },
  { name: 'flex', prefix: 'FL', path: APP_PATH_FL },
  { name: "apex_p", prefix: "AP", path: APP_PATH_AP },
]
