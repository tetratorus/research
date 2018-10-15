/* global assert, contract, artifacts, it */
var Elliptic = require('ec-altbn128').ec
var ec = new Elliptic('altbn128')
var BN = require('bn.js')
var EC = artifacts.require('EC')

var keccak256 = require('../../utils/keccak256.js')
var random = require('../../utils/random.js')(ec)
var schnorr = require('../../src/schnorr_altbn128.js')
var schnorrBlindSignature = require("../../src/schnorrBlindSignature.js")

contract('Schnorr Tests', function (accounts) {
  it('should sign and verify', function () {
    // generate
    var m = 'this is a random message'
    var priv = random(32)
    var privC = ec.curve.n.sub(priv).umod(ec.curve.n) // note: inverse is using n
    var y = ec.curve.g.mul(privC)
    var k = random(32)
    var schnorrSig = schnorr.sign(m, priv, k)

    // verify
    assert(schnorr.verify(schnorrSig.s, schnorrSig.e, y, m))
  })

  it('should sign and verify on-chain', async function () {
    // generate
    var m = 'this is a random message'
    var priv = random(32)

    var privC = ec.curve.n.sub(priv).umod(ec.curve.n) // note: inverse is using n
    var y = ec.curve.g.mul(privC)
    var k = random(32)
    var schnorrSig = schnorr.sign(m, priv, k)

    // verify
    var instance = await EC.deployed()
    var res = await instance.verifySchnorrSignatureOnMessage(
      '0x' + y.getX().toString(16, 64),
      '0x' + y.getY().toString(16, 64),
      m,
      '0x' + schnorrSig.e.toString(16, 64),
      '0x' + schnorrSig.s.toString(16, 64)
    )
    assert.equal(res, true)
  })

  it('should blind schnorr sign and verify on-chain', async function () {
    // generate params
    var m = 'this is a random message'
    var priv = random(32)
    var privInv = ec.curve.n.sub(priv).umod(ec.curve.n)
    var y = ec.curve.g.mul(privInv)

    var abstractedCommitment = schnorrBlindSignature.generateCommitment()

    // generate commitment
    var k = random(32)
    var r = ec.curve.g.mul(k)

    // generate blinding params
    var alpha = random(32)
    var beta = random(32)

    // blind commitment
    var rprime = r.add(ec.curve.g.mul(alpha)).add(y.mul(beta))
    var eprime = new BN(keccak256(m + rprime.getX().toString()), 16)
    var e = eprime.sub(beta).umod(ec.curve.n)

    var abstractedBlindCommitment = schnorrBlindSignature.generateBlindingCommitment(m, abstractedCommitment.r, y)

    // sign
    var s = k.add(priv.mul(e)).umod(ec.curve.n)

    var abstractedSignature = schnorrBlindSignature.sign(m, priv, abstractedBlindCommitment.e, abstractedCommitment.k)

    // verify blind schnorr
    assert.equal(ec.curve.g.mul(s).add(y.mul(e)).getX().toString(16, 64), r.getX().toString(16, 64))
    
    assert.equal(schnorrBlindSignature.verify(abstractedSignature.s, y, abstractedBlindCommitment.e, abstractedCommitment.r), true)

    // verify blind schnorr on-chain
    var instance = await EC.deployed()
    var res = await instance.verifySchnorrSignature(
      '0x' + y.getX().toString(16, 64),
      '0x' + y.getY().toString(16, 64),
      '0x' + r.getX().toString(16, 64),
      '0x' + e.toString(16, 64),
      '0x' + s.toString(16, 64)
    )
    assert.equal(res, true)

    // deblind
    var sprime = s.add(alpha).umod(ec.curve.n)

    // verify deblinded schnorr
    assert.equal(ec.curve.g.mul(sprime).add(y.mul(eprime)).getX().toString(16, 64), rprime.getX().toString(16, 64))

    // verify deblinded schnorr on-chain, note: we probably don't want to do this ever
    var res2 = await instance.verifySchnorrSignature(
      '0x' + y.getX().toString(16, 64),
      '0x' + y.getY().toString(16, 64),
      '0x' + rprime.getX().toString(16, 64),
      '0x' + eprime.toString(16, 64),
      '0x' + sprime.toString(16, 64)
    )
    assert.equal(res2, true)

    var res3 = await instance.verifySchnorrSignatureOnMessage(
      '0x' + y.getX().toString(16, 64),
      '0x' + y.getY().toString(16, 64),
      m,
      '0x' + eprime.toString(16, 64),
      '0x' + sprime.toString(16, 64)
    )
    assert.equal(res3, true)
  })

  // it should schnorr ring sign multiple parties and verify on-chain
  // it should encrypt blinding params
  // it should decrypt blinding params
  // it should allow source-expert simulated flow
  // it should designated verifier extend...?
})
