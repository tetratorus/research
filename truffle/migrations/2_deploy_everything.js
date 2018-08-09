var Schnorr = artifacts.require("Schnorr");
var Repository = artifacts.require("Repository");

module.exports = function(deployer) {
  deployer.deploy(Repository);
};
