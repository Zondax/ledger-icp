const Zemu = require('@zondax/zemu')

const catchExit = () => {
  process.on('SIGINT', async () => {
    await Zemu.default.stopAllEmuContainers()
    process.exit()
  })
}

module.exports = async () => {
  catchExit()
  await Zemu.default.checkAndPullImage()
  await Zemu.default.stopAllEmuContainers()
}
