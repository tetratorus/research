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

var getPointFromX = function(x) {
  while (true) {
    try {
      return ec.curve.pointFromX(x)
    } catch (e) {
      x = x.add(new BN(1))
    }
  }
}

contract('Ring Tests', function(accounts) {
  
  it('should schnorr ring sign and verify between two parties', function() {
    // generate params, where signer has index 0
    var loop = true
    while (loop) {
      var priv0 = random(32)
      var priv0Inv = ec.curve.n.sub(priv0).umod(ec.curve.n)
      var y0 = ec.curve.g.mul(priv0Inv) // y = g^-x, note: always use this form
      var priv1 = random(32)
      while (priv1.eq(priv0)) {
        priv1 = random(32)
      }
      var priv1Inv = ec.curve.n.sub(priv1).umod(ec.curve.n)
      var y1 = ec.curve.g.mul(priv1Inv)
      var a0 = random(32)
      var a1 = random(32)
      while (a1.eq(a0)) {
        a1 = random(32)
      }
      var R1 = ec.curve.g.mul(a1)
      var m = "this is a random message"
      var hmr1 = keccak256(m + R1.getX().toString())
      var hmr1Inv = ec.curve.n.sub(new BN(hmr1, 16)).umod(ec.curve.n)
      var R0 = ec.curve.g.mul(a0).add(y1.mul(new BN(hmr1, 16)))
      if (R0.getX().toString() !== "1" && R0.getX().toString() !== R1.getX().toString()) {
        loop = false
      }
    }
    assert.equal(R0.getX().toString(16, 64), ec.curve.g.mul(a0).add(ec.curve.g.mul(priv1.mul(hmr1Inv))).getX().toString(16, 64))

    // generate sigma
    var hmr0 = keccak256(m + R0.getX().toString())
    var hmr0Inv = ec.curve.n.sub(new BN(hmr0, 16)).umod(ec.curve.n)
    var sigma = a0.add(a1).add(priv0.mul(new BN(hmr0, 16)))

    // verify
    var lhs = ec.curve.g.mul(sigma)
    var rhs = R0.add(R1).add(y0.mul(hmr0Inv)).add(y1.mul(hmr1Inv))
    assert.equal(lhs.getX().toString(16, 64), rhs.getX().toString(16, 64))
  })

  it('should unique ring sign and verify between two parties', function() {
    // https://fc13.ifca.ai/proc/5-1.pdf
    // generate params
    var m = "this is a random message" // message
    var priv0 = random(32) // signer secret
    var priv0Inv = ec.curve.n.sub(priv0).umod(ec.curve.n) // inverse of secret = -x
    var y0 = ec.curve.g.mul(priv0Inv) // note: y = g^-x,
    do {
      // create other signer public key, whose secret we don't know
      var y1 = getPointFromX(random(32)) // note: the getX() value of this might not = x, if invalid point
    } while (y1.eq(y0))
    var R = [] // list of signers
    R.push([y0.getX().toString(), y0.getY().toString()])
    R.push([y1.getX().toString(), y1.getY().toString()])
    // generate params for other signer
    var c1 = random(32)
    var c1Inv = ec.curve.n.sub(c1).umod(ec.curve.n)
    var t1 = random(32)
    var a1 = ec.curve.g.mul(t1).add(y1.mul(c1Inv))
    var hmr = keccak256(m + R[0][0] + R[0][1] + R[1][0] + R[1][1])
    var hmrP = getPointFromX(new BN(hmr, 16))
    var b1 = hmrP.mul(t1).add(hmrP.mul(priv0).mul(c1))
    // generate params for signer
    var r0 = random(32)
    var a0 = ec.curve.g.mul(r0)
    var b0 = hmrP.mul(r0)
    var c0 = (new BN(keccak256(m + R[0][0] + R[0][1] + R[1][0] + R[1][1] + a0.getX().toString() + b0.getX().toString() + a1.getX().toString() + b1.getX().toString()), 16)).sub(c1)
    var c0Inv = ec.curve.n.sub(c0).umod(ec.curve.n)
    var t0 = r0.sub(c0.mul(priv0)).umod(ec.curve.n)
    var tau = hmrP.mul(priv0)

    // verify
    assert.equal(c0.add(c1).toString(), (new BN(keccak256(m + R[0][0] + R[0][1] + R[1][0] + R[1][1]
    + ec.curve.g.mul(t0).add(y0.mul(c0Inv)).getX().toString()
    + getPointFromX(new BN(keccak256(m + R[0][0] + R[0][1] + R[1][0] + R[1][1]), 16)).mul(t0).add(tau.mul(c0)).getX().toString()
    + ec.curve.g.mul(t1).add(y1.mul(c1Inv)).getX().toString()
    + getPointFromX(new BN(keccak256(m + R[0][0] + R[0][1] + R[1][0] + R[1][1]), 16)).mul(t1).add(tau.mul(c1)).getX().toString()
    ), 16)).toString())
  })

  // it should schnorr ring sign multiple parties and verify
  // it should schnorr ring sign multiple parties and verify on-chain
  // it should encrypt blinding params
  // it should decrypt blinding params
  // it should allow source-expert simulated flow
  // it should designated verifier extend...?

})
