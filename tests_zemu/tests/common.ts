import {DEFAULT_START_OPTIONS, DeviceModel} from "@zondax/zemu";

const Resolve = require('path').resolve
const APP_PATH_S = Resolve('../app/output/app_s.elf')
const APP_PATH_X = Resolve('../app/output/app_x.elf')

const APP_SEED = 'equip will roof matter pink blind book anxiety banner elbow sun young'

export const DEFAULT_OPTIONS = {
  ...DEFAULT_START_OPTIONS,
  logging: true,
  custom: `-s "${APP_SEED}"`,
  startText: 'Computer',
  X11: false,
}

export const DEVICE_MODELS: DeviceModel[] = [
  { name: 'nanos', prefix: 'S', path: APP_PATH_S },
  { name: 'nanox', prefix: 'X', path: APP_PATH_X },
]
