var bitcore = require('bitcore-lib')
var elliptic = require('ec-altbn128').ec
var ec = new elliptic('altbn128')
var ECIES = require('bitcore-ecies')()
var BN = require('bn.js')
var EC = artifacts.require('EC')
var crypto = require('crypto')

function random(bytes){
  do {
      var k = new BN(crypto.randomBytes(bytes));
  } while (k.toString() == "0" && k.gcd(ec.curve.n).toString() != "1")
  return k;
}

contract('Schnorr Tests', function(accounts) {
  
  it('should sign and verify', async function() {
    var k = random(32)
    console.log(k)
  })


})
