/* global artifacts */
var Repository = artifacts.require('Repository')
var EC = artifacts.require('EC')
var altbn128 = artifacts.require('altbn128')
var secp256k1 = artifacts.require('secp256k1')
var secp256k1GasEvaluator = artifacts.require('secp256k1GasEvaluator')
module.exports = function (deployer) {
  deployer.deploy(altbn128)
  deployer.link(altbn128, EC)
  deployer.deploy(EC)
  deployer.link(EC, Repository)
  deployer.deploy(Repository)

  deployer.deploy(secp256k1)
  deployer.link(secp256k1, secp256k1GasEvaluator)
  deployer.deploy(secp256k1GasEvaluator)
}
