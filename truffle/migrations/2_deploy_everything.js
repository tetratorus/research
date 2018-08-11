var Repository = artifacts.require('Repository');
var Schnorr = artifacts.require('Schnorr')

module.exports = function(deployer) {
  deployer.deploy(Schnorr);
  deployer.link(Schnorr, Repository);
  deployer.deploy(Repository);
};
