var Repository = artifacts.require('Repository')
var EC = artifacts.require('EC')
var altbn128 = artifacts.require('altbn128')

module.exports = function(deployer) {
  deployer.deploy(altbn128)
  deployer.link(altbn128, EC)
  deployer.deploy(EC)
  deployer.link(EC, Repository)
  deployer.deploy(Repository)
}
