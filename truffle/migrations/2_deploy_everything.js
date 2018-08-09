var Schnorr = artifacts.require("Schnorr");
var Repository = artifacts.require("Repository");

module.exports = function(deployer) {
  deployer.deploy(Schnorr);
  deployer.link(Schnorr, Repository);
  deployer.deploy(Repository);
};
