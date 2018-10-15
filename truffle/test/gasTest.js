/* global assert, contract, artifacts, it */
var Elliptic = require('elliptic').ec
var ec = new Elliptic('secp256k1')
var BN = require('bn.js')
// var ethCurve = artifacts.require('secp256k1')
var secp256k1GasEvaluator = artifacts.require('secp256k1GasEvaluator')

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

contract('Gas Tests (secp256k1)', function (accounts) {
  it('should cost reasonable gas for point addition', async function () {
    var k = random(32)
    var gk = ec.curve.g.mul(k)
    var l = random(32)
    var gl = ec.curve.g.mul(l)
    var instance = await secp256k1GasEvaluator.deployed()
    var res = await instance.evaluatePointAdd(
      ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')],
      ['0x' + gl.getX().toString(16).padStart(64, '0'), '0x' + gl.getY().toString(16).padStart(64, '0')]
    )
    console.log(res)
  })
  it('should cost reasonable gas for point doubling', async function () {
    var k = random(32)
    var gk = ec.curve.g.mul(k)
    var instance = await secp256k1GasEvaluator.deployed()
    var res = await instance.evaluatePointAdd(
      ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')],
      ['0x' + gk.getX().toString(16).padStart(64, '0'), '0x' + gk.getY().toString(16).padStart(64, '0')]
    )
    console.log(res)
  })
  it('should cost reasonable gas for point multiplication', function () {
    var k = random(32)
    
  })
})
