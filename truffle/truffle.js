var HDWalletProvider = require("truffle-hdwallet-provider");
var NonceTrackerSubprovider = require("web3-provider-engine/subproviders/nonce-tracker")
var secrets = require('../secrets.json')

var infura_apikey = secrets.infura_apikey;
var mnemonic = secrets.mnemonic;

module.exports = {
  // See <http://truffleframework.com/docs/advanced/configuration>
  // to customize your Truffle configuration!
  networks: {
    development: {
      host: "127.0.0.1",
      port: 7545,
      network_id: "*", // Match any network id
      gas: 4612388,
      gasPrice: 50000000000,
    },
    ropsten: {
      provider: new HDWalletProvider(mnemonic, "https://ropsten.infura.io/" + infura_apikey),
      network_id: 3,
      gas: 4612388, // Gas limit used for deploys
      gasPrice: 50000000000,
    },
    mainnet: {
      provider: function () {
        var wallet = new HDWalletProvider(mnemonic, 'https://mainnet.infura.io/' + infura_apikey)
        var nonceTracker = new NonceTrackerSubprovider()
        wallet.engine._providers.unshift(nonceTracker)
        nonceTracker.setEngine(wallet.engine)
        return wallet
      },
      network_id: 1,
      gasPrice: 5000000000,
    }
  }
};
