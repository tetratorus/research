var bitcore = require('bitcore-lib')
var elliptic = require('ec-altbn128').ec
var ec = new elliptic('altbn128')
var ECIES = require('bitcore-ecies')()
var BN = require('bn.js')
var EC = artifacts.require('EC')
var crypto = require('crypto')
var createKeccakHash = require('keccak')

function keccak256(inp){
  return createKeccakHash('keccak256').update(inp.toString()).digest('hex');
}

function random(bytes){
  do {
      var k = new BN(crypto.randomBytes(bytes));
  } while (k.toString() == "0" && k.gcd(ec.curve.n).toString() != "1")
  return k;
}

contract('Schnorr Tests', function(accounts) {
  
  it('should sign and verify', async function() {
    // generate
    var m = "this is a random message"
    var priv = random(32)
    var y = ec.curve.g.mul(priv)
    var k = random(32)
    var R = ec.curve.g.mul(k)
    var r = keccak256(m + R.getX().toString())
    var s = k.sub(priv.mul(new BN(r, 16)))
    // verify
    assert.equal(r, keccak256(m + y.mul(new BN(r, 16)).add(ec.curve.g.mul(s)).getX().toString()))
  })


})
