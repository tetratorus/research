/* global assert, contract, artifacts, it */
var Elliptic = require('elliptic').ec
var ec = new Elliptic('secp256k1')
var BN = require('bn.js')
var ethCurve = artifacts.require('secp256k1')

var keccak256 = require('../../utils/keccak256.js')
var random = require('../../utils/random.js')(ec)
var schnorr = require('../../src/schnorr_secp256k1.js')
var schnorrBlindSignature = require("../../src/schnorrBlindSignature.js")
var origMul = ec.curve.g.mul
var log = []
ec.curve.g.mul = function() {
  var res = origMul.apply(this, arguments)
  log.push([res.getX().toString(16).padStart(64, '0'), res.getY().toString(16).padStart(64, '0')])
  return res
}.bind(ec.curve.g)

contract('Schnorr Tests (secp256k1)', function (accounts) {
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

  it('should curve multiply on-chain', async function () {
    var k = random(32)
    var gk = ec.curve.g.mul(k)
    var instance = await ethCurve.deployed()
    var gkXY = ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')]
    var res = await instance.hackyScalarBaseMult('0x' + k.toString(16).padStart(64, '0'), gkXY, [0])
    assert.equal(res[0].toString(16).padStart(64, '0'), gk.getX().toString(16).padStart(64, '0'))
  })

  it('should invmod on-chain', async function () {
    var k = random(32)
  })

  it('should curve add on-chain', async function () {
    var k = random(32)
    var gk = ec.curve.g.mul(k)
    var l = random(32)
    var gl = ec.curve.g.mul(l)
    var gsum = gk.add(gl)
    assert.equal(ec.curve.g.mul(k.add(l).mod(ec.curve.n)).getX().toString(16).padStart(64, '0'), gsum.getX().toString(16).padStart(64, '0'))
    var instance = await ethCurve.deployed()
    var res = await instance.pointAdd(
      ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')],
      ['0x' + gl.getX().toString(16).padStart(64, '0'), '0x' + gl.getY().toString(16).padStart(64, '0')]
    )
    assert.equal(res[0].toString(16).padStart(64, '0'), gsum.getX().toString(16).padStart(64, '0'))
    assert.equal(res[1].toString(16).padStart(64, '0'), gsum.getY().toString(16).padStart(64, '0'))
    var g2k = gk.dbl()
    var res = await instance.pointAdd(
      ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')],
      ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')]
    )
    assert.equal(res[0].toString(16).padStart(64, '0'), g2k.getX().toString(16).padStart(64, '0'))
    assert.equal(res[1].toString(16).padStart(64, '0'), g2k.getY().toString(16).padStart(64, '0'))
  })

  it('should sign and verify on-chain', async function () {
    // generate
    var m = 'this is a random message'
    var priv = random(32)

    var privC = ec.curve.n.sub(priv).umod(ec.curve.n) // note: inverse is using n
    var y = ec.curve.g.mul(privC)
    var k = random(32)
    var schnorrSig = schnorr.sign(m, priv, k)
    var ye = y.mul(new BN(schnorrSig.e, 16))
    var gs = ec.curve.g.mul(schnorrSig.s)
    var points = [
      '0x' + ye.getX().toString(16).padStart(64, '0'),
      '0x' + ye.getY().toString(16).padStart(64, '0'),
      '0x' + gs.getX().toString(16).padStart(64, '0'),
      '0x' + gs.getY().toString(16).padStart(64, '0')
    ]
    // verify
    var instance = await ethCurve.deployed()
    var res = await instance.verifySchnorrSignatureOnMessage(
      ['0x' + y.getX().toString(16).padStart(64, '0'),
      '0x' + y.getY().toString(16).padStart(64, '0')],
      m,
      '0x' + schnorrSig.e.toString(16).padStart(64, '0'),
      '0x' + schnorrSig.s.toString(16).padStart(64, '0'),
      points,
      [0]
    )
    assert.equal(res, true)
    // console.log(log)
  })

  // it('should blind schnorr sign and verify on-chain', async function () {
  //   // generate params
  //   var m = 'this is a random message'
  //   var priv = random(32)
  //   var privInv = ec.curve.n.sub(priv).umod(ec.curve.n)
  //   var y = ec.curve.g.mul(privInv)

  //   var abstractedCommitment = schnorrBlindSignature.generateCommitment()

  //   // generate commitment
  //   var k = random(32)
  //   var r = ec.curve.g.mul(k)

  //   // generate blinding params
  //   var alpha = random(32)
  //   var beta = random(32)

  //   // blind commitment
  //   var rprime = r.add(ec.curve.g.mul(alpha)).add(y.mul(beta))
  //   var eprime = new BN(keccak256(m + rprime.getX().toString()), 16)
  //   var e = eprime.sub(beta).umod(ec.curve.n)

  //   var abstractedBlindCommitment = schnorrBlindSignature.generateBlindingCommitment(m, abstractedCommitment.r, y)

  //   // sign
  //   var s = k.add(priv.mul(e)).umod(ec.curve.n)

  //   var abstractedSignature = schnorrBlindSignature.sign(m, priv, abstractedBlindCommitment.e, abstractedCommitment.k)

  //   // verify blind schnorr
  //   assert.equal(ec.curve.g.mul(s).add(y.mul(e)).getX().toString(16).padStart(64, '0'), r.getX().toString(16).padStart(64, '0'))
    
  //   assert.equal(schnorrBlindSignature.verify(abstractedSignature.s, y, abstractedBlindCommitment.e, abstractedCommitment.r), true)

  //   // verify blind schnorr on-chain
  //   var instance = await ethCurve.deployed()
  //   var res = await instance.verifySchnorrSignature(
  //     '0x' + y.getX().toString(16).padStart(64, '0'),
  //     '0x' + y.getY().toString(16).padStart(64, '0'),
  //     '0x' + r.getX().toString(16).padStart(64, '0'),
  //     '0x' + e.toString(16).padStart(64, '0'),
  //     '0x' + s.toString(16).padStart(64, '0')
  //   )
  //   assert.equal(res, true)

  //   // deblind
  //   var sprime = s.add(alpha).umod(ec.curve.n)

  //   // verify deblinded schnorr
  //   assert.equal(ec.curve.g.mul(sprime).add(y.mul(eprime)).getX().toString(16).padStart(64, '0'), rprime.getX().toString(16).padStart(64, '0'))

  //   // verify deblinded schnorr on-chain, note: we probably don't want to do this ever
  //   var res2 = await instance.verifySchnorrSignature(
  //     '0x' + y.getX().toString(16).padStart(64, '0'),
  //     '0x' + y.getY().toString(16).padStart(64, '0'),
  //     '0x' + rprime.getX().toString(16).padStart(64, '0'),
  //     '0x' + eprime.toString(16).padStart(64, '0'),
  //     '0x' + sprime.toString(16).padStart(64, '0')
  //   )
  //   assert.equal(res2, true)

  //   var res3 = await instance.verifySchnorrSignatureOnMessage(
  //     '0x' + y.getX().toString(16).padStart(64, '0'),
  //     '0x' + y.getY().toString(16).padStart(64, '0'),
  //     m,
  //     '0x' + eprime.toString(16).padStart(64, '0'),
  //     '0x' + sprime.toString(16).padStart(64, '0')
  //   )
  //   assert.equal(res3, true)
  // })

  // it should schnorr ring sign multiple parties and verify on-chain
  // it should encrypt blinding params
  // it should decrypt blinding params
  // it should allow source-expert simulated flow
  // it should designated verifier extend...?
})
