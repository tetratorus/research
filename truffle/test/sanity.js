var bitcore = require('bitcore-lib');
var ECIES = require('bitcore-ecies')();
var Schnorr = artifacts.require('Schnorr');
// var contract = artifacts.require("ContractName");

contract('Sanity Tests', function(accounts) {
  it("should encrypt and decrypt data", function() {
    
    var alicePrivateKey = new bitcore.PrivateKey('10274ACD1126740A07688CE5C8FEB13EC298413781B2B8565948A82F7A1E42D4');
    var bobPrivateKey = new bitcore.PrivateKey('55AF2C88EAC3F5B97DBD916C0477C86DE36C6B3C34AA1662840B24ECD93FD42A');
    debugger;
    var data = new Buffer.from('The is a raw data example');
    
    // Encrypt data
    var cypher1 = ECIES.privateKey(alicePrivateKey).publicKey(bobPrivateKey.publicKey);
    var encrypted = cypher1.encrypt(data);
    
    // Decrypt data
    var cypher2 = ECIES.privateKey(bobPrivateKey).publicKey(alicePrivateKey.publicKey);
    var decrypted = cypher2.decrypt(encrypted);
    
    assert.equal(data.toString(), decrypted.toString());
  });

  it("should convert integer to string", async function() {
    await Schnorr.deployed().then(async function(instance) {
      await instance.uintToString(25).then(function(res) {
        return assert.equal("25", res);
      }).catch(function(e) {
        throw e;
      })
      return true
    });
  })

  it("should sign and verify Schnorr signature", function() {
    return
  })
});
