var Elliptic = require('ec-altbn128').ec
var ec = new Elliptic('altbn128')
var BN = require('bn.js')
var keccak256 = require('../utils/keccak256.js')

var schnorr = {}
schnorr.sign = function (m, priv, k) {
  // var privInv = ec.curve.n.sub(priv).umod(ec.curve.n) // note: inverse is using n
  // var y = ec.curve.g.mul(privInv)
  var r = ec.curve.g.mul(k)
  var e = keccak256(m + r.getX().toString())
  var s = k.add(priv.mul(new BN(e, 16))).umod(ec.curve.n)

  return {s: s, e: e}
}

schnorr.verify = function (s, e, y, m) {
  var r = y.mul(new BN(e, 16)).add(ec.curve.g.mul(s))

  return e === keccak256(m + r.getX().toString())
}
module.exports = schnorr
