var Elliptic = require('ec-altbn128').ec
var ec = new Elliptic('altbn128')
var BN = require('bn.js')
var keccak256 = require('../utils/keccak256.js')
var random = require('../utils/random.js')(ec)

var schnorrBlindSignature = {}

schnorrBlindSignature.randomKeys = function (n) {
  var keys = []
  for (let i = 0; i < n; i++) {
    var privK = random(32)
    var privKInv = ec.curve.n.sub(privK).umod(ec.curve.n) // y = g^-x
    var pubK = ec.curve.g.mul(privKInv)
    keys.push({pubK: pubK, privK: privK})
  }
  return keys
}

schnorrBlindSignature.generateCommitment = function () {
  // generate commitment
  var k = random(32)
  var r = ec.curve.g.mul(k)
  return {k: k, r: r};
}

schnorrBlindSignature.generateBlindingCommitment = function(m, r, pubK) {
  var alpha = random(32)
  var beta = random(32)

  // blind commitment
  var rprime = r.add(ec.curve.g.mul(alpha)).add(pubK.mul(beta))
  var eprime = new BN(keccak256(m + rprime.getX().toString()), 16)
  var e = eprime.sub(beta).umod(ec.curve.n)

  return {alpha:alpha, beta: beta, e:e}
}

schnorrBlindSignature.sign = function (m, privK, e, k) {
  var s = k.add(privK.mul(e)).umod(ec.curve.n)
  return {s:s}
}

schnorrBlindSignature.verify = function (s, pubK, e, r) {
  return ec.curve.g.mul(s).add(pubK.mul(e)).getX().toString(16, 64) === r.getX().toString(16, 64)
}

schnorrBlindSignature.deblind = function(s, alpha) {
  return {sprime: s.add(alpha).umod(ec.curve.n)}
}


module.exports = schnorrBlindSignature;