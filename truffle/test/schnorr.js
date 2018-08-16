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
    var priv = random(32)
    var k = random(32)
    // generate R = g^k
    var R = ec.curve.g.mul(k)
  })


})
