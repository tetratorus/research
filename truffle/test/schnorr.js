var bitcore = require('bitcore-lib')
var elliptic = require('ec-altbn128').ec
var ec = new elliptic('altbn128')
var ECIES = require('bitcore-ecies')()
var BN = require('bn.js')
var EC = artifacts.require('EC')
var crypto = require('crypto')
var keccak256 = require('../../utils/keccak256.js');
var random = require('../../utils/random.js')(ec);
var schnorr = require('../../src/schnorr.js');

contract('Schnorr Tests', function(accounts) {
  
  it('should sign and verify', function() {
    // generate
    var m = "this is a random message"
    var priv = random(32)
    var privC = ec.curve.n.sub(priv).umod(ec.curve.n) // note: inverse is using n
    var y = ec.curve.g.mul(privC)
    var schnorrSig = schnorr.sign(m, priv);
    
    // verify
    assert(schnorr.verify(schnorrSig.s, schnorrSig.e, y, m));
  })
  
  it('should sign and verify on-chain', async function() {
    // generate
    var m = "this is a random message"
    var priv = random(32)
    var privC = ec.curve.n.sub(priv).umod(ec.curve.n) // note: inverse is using n
    var y = ec.curve.g.mul(privC)
    var schnorrSig = schnorr.sign(m, priv);

    // verify
    var instance = await EC.deployed()
    var res = await instance.verifySchnorrSignature(
      '0x'+y.getX().toString(16, 64),
      '0x'+y.getY().toString(16, 64),
      m,
      '0x'+schnorrSig.e.toString(16, 64),
      '0x'+schnorrSig.s.toString(16, 64)
    )
    assert.equal(res, true)
  })

  // it should blind schnorr sign
  // it should blind schnorr verify
  // it should blind schnorr verify on-chain
  // it should deblind and schnorr verify
  // it should deblind and schnorr verify on-chain
  // it should encrypt blinding params
  // it should decrypt blinding params
  // it should allow source-expert simulated flow
  // it should ring sign?
  // it should schnorr ring sign?
  // it should designated verifier extend...?

})
