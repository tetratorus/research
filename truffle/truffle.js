var HDWalletProvider = require('truffle-hdwallet-provider')
var NonceTrackerSubprovider = require('web3-provider-engine/subproviders/nonce-tracker')
var secrets = require('../secrets.json')

var INFURA_API_KEY = secrets.INFURA_API_KEY
var MNEMONIC = secrets.MNEMONIC

module.exports = {
  // See <http://truffleframework.com/docs/advanced/configuration>
  // to customize your Truffle configuration!
  networks: {
    development: {
      host: '127.0.0.1',
      port: 7545,
      network_id: '*', // Match any network id
      gas: 4612388,
      gasPrice: 50000000000
    },
    ropsten: {
      provider: new HDWalletProvider(MNEMONIC, 'https://ropsten.infura.io/' + INFURA_API_KEY),
      network_id: 3,
      gas: 4612388, // Gas limit used for deploys
      gasPrice: 50000000000
    },
    mainnet: {
      provider: function () {
        var wallet = new HDWalletProvider(MNEMONIC, 'https://mainnet.infura.io/' + INFURA_API_KEY)
        var nonceTracker = new NonceTrackerSubprovider()
        wallet.engine._providers.unshift(nonceTracker)
        nonceTracker.setEngine(wallet.engine)
        return wallet
      },
      network_id: 1,
      gasPrice: 5000000000
    }
  }
}
