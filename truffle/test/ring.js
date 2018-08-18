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
    var priv0 = random(32) // generate secret
    var priv0Inv = ec.curve.n.sub(priv0).umod(ec.curve.n)
    var y0 = ec.curve.g.mul(priv0Inv) // y = g^-x, note: always use this form
    var y1 = getPointFromX(random(32)) // generate other signer whose secret we don't know
    var loop = true
    while (loop) {
      var a0 = random(32)
      var a1 = random(32)
      while (a1.eq(a0)) { // make sure random numbers aren't the same
        a1 = random(32)
      }
      var R1 = ec.curve.g.mul(a1)
      var m = "this is a random message"
      var hmr1 = keccak256(m + R1.getX().toString())
      var hmr1Inv = ec.curve.n.sub(new BN(hmr1, 16)).umod(ec.curve.n)
      var R0 = ec.curve.g.mul(a0).add(y1.mul(new BN(hmr1, 16)))
      if (R0.getX().toString() !== "1" && R0.getX().toString() !== R1.getX().toString()) {
        loop = false // make sure they are pairwise distinct
      }
    }
    assert.equal(R0.getX().toString(16, 64), ec.curve.g.mul(a0).add(y1.mul(hmr1)).getX().toString(16, 64))

    // calculate sigma
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

  it('should designated verifier extend a schnorr message signature and verify', function() {
    // generate params for underlying message
    var k = random(32)
    var r = ec.curve.g.mul(k)
    var privSource = random(32)
    var privSourceInv = ec.curve.n.sub(privSource).umod(ec.curve.n)
    var ySource = ec.curve.g.mul(privSourceInv) // y = g^-x
    var schnorrSig = schnorr.sign("this is a random message", privSource, k)
    var e = schnorrSig.e
    var s = schnorrSig.s
    var sInv = ec.curve.n.sub(s).umod(ec.curve.n)
    assert(schnorr.verify(s, e, ySource, "this is a random message"))

    // delete secrets to be sure that they are not used later in generating the DV signature
    k = null
    privSource = null
    privSourceInv = null
    var gsInv = ec.curve.g.mul(sInv)

    // generate params for reader (i.e. designated verifier)
    var yReader = getPointFromX(random(32)) // we don't know the reader's secret


    // designated verifier extension on underlying message
    // which is just a schnorr ring sig but over a g^s instead of g^x

    // generate params
    var m = "this is a random message" // this is optional, we may want to use it for tagging
    var loop = true
    while (loop) {
      var a0 = random(32)
      var a1 = random(32)
      while (a1.eq(a0)) {
        a1 = random(32)
      }
      var R1 = ec.curve.g.mul(a1)
      var hmr1 = keccak256(m + R1.getX().toString())
      var hmr1Inv = ec.curve.n.sub(new BN(hmr1, 16)).umod(ec.curve.n)
      var R0 = ec.curve.g.mul(a0).add(yReader.mul(new BN(hmr1, 16)))
      if (R0.getX().toString() !== "1" && R0.getX().toString() !== R1.getX().toString()) {
        loop = false // make sure they are pairwise distinct
      }
    }

    // calculate sigma
    var hmr0 = keccak256(m + R0.getX().toString())
    var hmr0Inv = ec.curve.n.sub(new BN(hmr0, 16)).umod(ec.curve.n)
    var sigma = a0.add(a1).add(s.mul(new BN(hmr0, 16)))

    // remove s and sInv to ensure that they aren't revealed later
    // only gsInv should be used
    s = null
    sInv = null
    

    // verify
    var lhs = ec.curve.g.mul(sigma)
    var rhs = R0.add(R1).add(gsInv.mul(hmr0Inv)).add(yReader.mul(hmr1Inv))
    // verify ring sig
    assert.equal(lhs.getX().toString(16, 64), rhs.getX().toString(16, 64))
    var gs = gsInv.mul((new BN(-1)).umod(ec.curve.n))
    // verify underlying message is a valid signature
    assert.equal(gs.add(ySource.mul(new BN(keccak256(m + r.getX().toString()), 16))).getX().toString(16, 64), r.getX().toString(16, 64))

  })

  it('should forge a designated verifier signature and verify', function() {
    // generate params for underlying message
    var k = random(32)
    var r = ec.curve.g.mul(k)
    var privSource = random(32)
    var privSourceInv = ec.curve.n.sub(privSource).umod(ec.curve.n)
    var ySource = ec.curve.g.mul(privSourceInv) // y = g^-x
    var schnorrSig = schnorr.sign("this is a random message", privSource, k)
    var e = schnorrSig.e
    var s = schnorrSig.s
    var sInv = ec.curve.n.sub(s).umod(ec.curve.n)
    assert(schnorr.verify(s, e, ySource, "this is a random message"))
    var gsInv = ec.curve.g.mul(sInv)

    // remove params that the reader shouldnt have
    k = null
    privSource = null
    privSourceInv = null
    s = null
    sInv = null

    // generate params for reader
    var privReader = random(32)
    var privReaderInv = ec.curve.n.sub(privReader).umod(ec.curve.n)
    var yReader = ec.curve.g.mul(privReaderInv)

    // generate params
    var m = "this is a random message" // this is optional, we may want to use it for tagging
    var loop = true
    while (loop) {
      var a0 = random(32)
      var a1 = random(32)
      while (a1.eq(a0)) {
        a1 = random(32)
      }
      var R0 = ec.curve.g.mul(a0)
      var hmr0 = keccak256(m + R0.getX().toString())
      var hmr0Inv = ec.curve.n.sub(new BN(hmr0, 16)).umod(ec.curve.n)
      var R1 = ec.curve.g.mul(a1).add(gsInv.mul(new BN(hmr0, 16)))
      if (R1.getX().toString() !== "1" && R1.getX().toString() !== R0.getX().toString()) {
        loop = false // make sure they are pairwise distinct
      }
    }

    // calculate sigma
    var hmr1 = keccak256(m + R1.getX().toString())
    var hmr1Inv = ec.curve.n.sub(new BN(hmr1, 16)).umod(ec.curve.n)
    var sigma = a0.add(a1).add(privReader.mul(new BN(hmr1, 16)))

    // remove privReader and privReaderInv to ensure that they aren't revealed later
    privReader = null
    privReaderInv = null
    

    // verify
    var lhs = ec.curve.g.mul(sigma)
    var rhs = R0.add(R1).add(gsInv.mul(hmr0Inv)).add(yReader.mul(hmr1Inv))
    // verify ring sig
    assert.equal(lhs.getX().toString(16, 64), rhs.getX().toString(16, 64))
    var gs = gsInv.mul((new BN(-1)).umod(ec.curve.n))
    // verify underlying message is a valid signature
    assert.equal(gs.add(ySource.mul(new BN(keccak256(m + r.getX().toString()), 16))).getX().toString(16, 64), r.getX().toString(16, 64))

  })

  // it should validate form of underlying message signature
  // it should designated verifier extend a signed message and verify on-chain
  // it should schnorr ring sign multiple parties and verify
  // it should verify schnorr ring signatures on-chain
  // it should unique ring sign multiple parties and verify
  // it should unique ring sign multiple parties and be able to detect same signers
  // it should verify unique ring signature on multiple parties on-chain and detect same signers
  // it should encrypt blinding params
  // it should decrypt blinding params
  // it should allow source-expert simulated flow..?

})
