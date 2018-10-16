/* global assert, contract, artifacts, it */

/* hacky logging */
var BN = require('bn.js')
var logPoints = []
var logInvmods = []
var origRedInvm = BN.prototype.redInvm
BN.prototype.redInvm = function () {
  var res = origRedInvm.apply(this, arguments)
  if (loggingEnabled) {
    logInvmods.unshift('0x' + res.toString(16).padStart(64, '0'))
  }
  return res
}
var proxyquire = require('proxyquire')
var Elliptic = proxyquire('elliptic', {'bn.js': BN}).ec
var ec = new Elliptic('secp256k1')

var origMul = ec.curve.g.mul
var loggingEnabled = false
var startLogging = function (resume) {
  if (!resume) {
    logPoints = []
    logInvmods = []
  }
  loggingEnabled = true
  return resume
}
var stopLogging = function () {
  loggingEnabled = false
  return logPoints.concat(logInvmods)
}
ec.curve.g.mul = function () {
  var res = origMul.apply(this, arguments)
  if (loggingEnabled) {
    logPoints.push('0x' + res.getX().toString(16).padStart(64, '0'))
    logPoints.push('0x' + res.getY().toString(16).padStart(64, '0'))
  }
  return res
}.bind(ec.curve.g)

/* hacky logging */

// var ethCurve = artifacts.require('secp256k1')
var secp256k1GasEvaluator = artifacts.require('secp256k1GasEvaluator')

var keccak256 = require('../../utils/keccak256.js')
var random = require('../../utils/random.js')(ec)
var schnorr = require('../../src/schnorr_secp256k1.js')
var schnorrBlindSignature = require("../../src/schnorrBlindSignature.js")

contract('Gas Tests (secp256k1)', function (accounts) {
  it('should cost reasonable gas for point addition', async function () {
    var k = new BN('2c3cfa9cbd190d705357c454ec360c74fa399a2568121a818ce6e59acda83478', 16)
    var gk = ec.curve.g.mul(k)
    var l = new BN('96dde20fb11209a8a1ec8356f1dad824839156d7cd417d107ec7f9c8da2cd31a', 16)
    var gl = ec.curve.g.mul(l)
    var instance = await secp256k1GasEvaluator.deployed()
    var res = await instance.evaluatePointAdd(
      ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')],
      ['0x' + gl.getX().toString(16).padStart(64, '0'), '0x' + gl.getY().toString(16).padStart(64, '0')]
    )
    console.log(res.receipt.gasUsed)
  })
  it('should cost reasonable gas for point doubling', async function () {
    var k = new BN('f07cb6632594e00ab4bf5b11822ea98a7ab439d98c575b4e331074f203e2267c', 16)
    var gk = ec.curve.g.mul(k)
    var instance = await secp256k1GasEvaluator.deployed()
    var res = await instance.evaluatePointAdd(
      ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')],
      ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')]
    )
    console.log(res.receipt.gasUsed)
  })
  it('should cost reasonable gas for point multiplication', async function () {
    var k = new BN('43bf3706c8fc26fe34e03efc24752b7508209b2708e4514e16b8056fbda30616', 16)
    var gk = ec.curve.g.mul(k)
    var instance = await secp256k1GasEvaluator.deployed()
    var res = await instance.evaluateHackyScalarMult(
      ['0x' + ec.curve.g.getX().toString(16).padStart(64, '0'), '0x' + ec.curve.g.getY().toString(16).padStart(64, '0')],
      '0x' + k.toString(16).padStart(64, '0'),
      ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')],
      [0, 0]
    )
    console.log(res.receipt.gasUsed)
  })
  it('should cost reasonable gas for inverse modulo', async function () {
    var instance = await secp256k1GasEvaluator.deployed()
    var res = await instance.evaluateInvMod('0x69a40b9f7c9e4817ca19cdac8eacff0d0538c66a87476499d364dd047c12c117')
    console.log(res.receipt.gasUsed)
  })
  it('should cost reasonable gas for hacky inverse modulo', async function () {
    var instance = await secp256k1GasEvaluator.deployed()
    var red = BN.red(new BN('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 16))
    var k = new BN('69a40b9f7c9e4817ca19cdac8eacff0d0538c66a87476499d364dd047c12c117', 16);
    startLogging()
    var kInv = k.toRed(red).redInvm() // we are only tracking redInvm, so create a reduction context and use redInvm
    var precomputes = stopLogging()
    var res = await instance.evaluateHackyInvMod(
      '0x69a40b9f7c9e4817ca19cdac8eacff0d0538c66a87476499d364dd047c12c117',
      precomputes,
      [0, 0]
    )
    console.log(res.receipt.gasUsed)
  })
  it('should cost reasonable gas for hacky point addition', async function () {
    var k = new BN('2c3cfa9cbd190d705357c454ec360c74fa399a2568121a818ce6e59acda83478', 16)
    var gk = ec.curve.g.mul(k)
    var l = new BN('96dde20fb11209a8a1ec8356f1dad824839156d7cd417d107ec7f9c8da2cd31a', 16)
    var gl = ec.curve.g.mul(l)
    startLogging()
    var gsum = gk.add(gl)
    var precomputes = stopLogging()
    var instance = await secp256k1GasEvaluator.deployed()
    // note: order of addition matters because the precomputed modinv is different
    var res = await instance.evaluateHackyPointAdd(
      ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')],
      ['0x' + gl.getX().toString(16).padStart(64, '0'), '0x' + gl.getY().toString(16).padStart(64, '0')],
      precomputes,
      [0, 0]
    )
    console.log(res.receipt.gasUsed)
  })
})
