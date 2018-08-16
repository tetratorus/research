var bitcore = require('bitcore-lib')
var elliptic = require('ec-altbn128').ec
var ec = new elliptic('altbn128')
var ECIES = require('bitcore-ecies')()
var BN = require('bn.js')
var EC = artifacts.require('EC')

contract('Sanity Tests', function(accounts) {
  it('should encrypt and decrypt data', function() {
    
    var alicePrivateKey = new bitcore.PrivateKey('10274ACD1126740A07688CE5C8FEB13EC298413781B2B8565948A82F7A1E42D4')
    var bobPrivateKey = new bitcore.PrivateKey('55AF2C88EAC3F5B97DBD916C0477C86DE36C6B3C34AA1662840B24ECD93FD42A')
    var data = new Buffer.from('The is a raw data example')
    
    // Encrypt data
    var cypher1 = ECIES.privateKey(alicePrivateKey).publicKey(bobPrivateKey.publicKey)
    var encrypted = cypher1.encrypt(data)
    
    // Decrypt data
    var cypher2 = ECIES.privateKey(bobPrivateKey).publicKey(alicePrivateKey.publicKey)
    var decrypted = cypher2.decrypt(encrypted)
    
    assert.equal(data.toString(), decrypted.toString())
  })

  it('should convert integer to string', async function() {
    var instance = await EC.deployed()
    var res = await instance.uintToString(25)
    assert.equal('25', res)
    return true
  })
  
  
  it('should match solidity implementation (libGenOrder)', async function() {
    var instance = await EC.deployed()
    var solidityRes = await instance.libGenOrder()
    assert.equal(solidityRes.toString(16), ec.curve.n.toString(16))
  })
  
  it('should match solidity implementation (libFieldOrder)', async function() {
    var instance = await EC.deployed()
    var solidityRes = await instance.libFieldOrder()
    assert.equal(solidityRes.toString(16), ec.curve.p.toString(16))
  })
  
  it('should match solidity implementation (libGenerator)', async function() {
    var instance = await EC.deployed()
    var solidityP = await instance.libGenerator()
    assert.equal(solidityP[0].toString(16), ec.curve.g.getX().toString(16))
    assert.equal(solidityP[1].toString(16), ec.curve.g.getY().toString(16))
  })
  
  it('should match solidity implementation (libNegate)', async function() {
    var randomNumber = Math.floor(Math.random() * 1000)
    var instance = await EC.deployed()
    var solidityP = await instance.libScalarBaseMult(randomNumber)
    var ecurveP = ec.curve.g.mul(randomNumber)
    solidityP = await instance.libNegate(solidityP[0], solidityP[1])
    ecurveP = ecurveP.neg()
    assert.equal(solidityP[0].toString(16), ecurveP.getX().toString(16))
    assert.equal(solidityP[1].toString(16), ecurveP.getY().toString(16))
  })
  
  // // it('should match solidity implementation (libHashToPoint)', async function() {
  // //   // TODO
  // // })

  it('should match solidity implementation (libEqual)', async function() {

    var randomNumber = Math.floor(Math.random() * 1000)
    var instance = await EC.deployed()
    var solidityP = await instance.libScalarBaseMult(randomNumber)
    var ecurveP = ec.curve.g.mul(randomNumber)
    var solidityEqual = await instance.libEqual(solidityP[0], solidityP[1], solidityP[0], solidityP[1])
    var ecurveEqual = ecurveP.eq(ecurveP)
    assert.equal(ecurveEqual, solidityEqual)
  })


  it('should match solidity implementation (libFindYforX)', async function() {
    var randomNumber = Math.floor(Math.random() * 1000)
    var instance = await EC.deployed()
    var solidityP = await instance.libScalarBaseMult(randomNumber)
    var ecurveP = ec.curve.g.mul(randomNumber)
    assert.equal(solidityP[0].toString(16), ecurveP.getX().toString(16))
    var solidityP2 = await instance.libFindYforX('0x' + solidityP[0].toString(16))
    var ecurveP2 = ec.curve.pointFromX(ecurveP.getX())
    if (solidityP[1].toString(16) !== solidityP2[1].toString(16)) {
      solidityP2 = await instance.libNegate(solidityP2[0], solidityP2[1])
    }
    if (ecurveP.getY().toString(16) !== ecurveP2.getY().toString(16)) {
      ecurveP2 = ecurveP2.neg()
    }
    assert.equal(ecurveP2.getY().toString(16), solidityP2[1].toString(16))
  })
  
  it('should match solidity implementation (libIsInfinity)', async function() {
    var randomNumber = Math.floor(Math.random() * 1000)
    var instance = await EC.deployed()
    var solidityP = await instance.libScalarBaseMult(randomNumber)
    var ecurveP = ec.curve.g.mul(randomNumber)
    var solidityPn = await instance.libNegate(solidityP[0], solidityP[1])
    var ecurvePn = ecurveP.neg()
    var solidityInf = await instance.libPointAdd(solidityP[0], solidityP[1], solidityPn[0], solidityPn[1])
    var solidityIsInf = await instance.libIsInfinity(solidityInf[0], solidityInf[1])
    var ecurveInf = ecurveP.add(ecurvePn)
    assert.equal(ecurveInf.isInfinity(), solidityIsInf)
  })
  
  it('should match solidity implementation (libIsOnCurve)', async function() {
    var randomNumber = Math.floor(Math.random() * 1000)
    var instance = await EC.deployed()
    var solidityP = await instance.libScalarBaseMult(randomNumber)
    var ecurveP = ec.curve.g.mul(randomNumber)
    var solidityIsOnCurve = await instance.libIsOnCurve(solidityP[0], solidityP[1])
    var ecurveIsOnCurve = ec.curve.validate(ecurveP)
    assert.equal(ecurveIsOnCurve, solidityIsOnCurve)
  })
  
  it('should match solidity implementation (libScalarBaseMult)', async function() {
    var randomNumber = Math.floor(Math.random() * 1000)
    var instance = await EC.deployed()
    var solidityP = await instance.libScalarBaseMult(randomNumber)
    var ecurveP = ec.curve.g.mul(randomNumber)
    assert.equal(solidityP[0].toString(16), ecurveP.getX().toString(16))
    assert.equal(solidityP[1].toString(16), ecurveP.getY().toString(16))
  })
  
  it('should match solidity implementation (libPointAdd)', async function() {
    var randomNumber = Math.floor(Math.random() * 1000)
    var randomNumber2 = Math.floor(Math.random() * 1000)
    var instance = await EC.deployed()
    var solidityP = await instance.libScalarBaseMult(randomNumber)
    var solidityP2 = await instance.libScalarBaseMult(randomNumber2)
    var solidityR = await instance.libPointAdd(solidityP[0], solidityP[1], solidityP2[0], solidityP2[1])
    var ecurveP = ec.curve.g.mul(randomNumber)
    var ecurveP2 = ec.curve.g.mul(randomNumber2)
    var ecurveR = ecurveP.add(ecurveP2)
    assert.equal(solidityR[0].toString(16), ecurveR.getX().toString(16))
    assert.equal(solidityR[1].toString(16), ecurveR.getY().toString(16))
  })
  
  it('should match solidity implementation (libScalarMult)', async function() {
    var randomNumber = Math.floor(Math.random() * 1000)
    var randomNumber2 = Math.floor(Math.random() * 1000)
    var instance = await EC.deployed()
    var solidityP = await instance.libScalarBaseMult(randomNumber)
    var ecurveP = ec.curve.g.mul(randomNumber)
    var solidityP2 = await instance.libScalarMult(solidityP[0], solidityP[1], randomNumber2)
    var ecurveP2 = ecurveP.mul(randomNumber2)
    assert.equal(solidityP2[0].toString(16), ecurveP2.getX().toString(16))
    assert.equal(solidityP2[1].toString(16), ecurveP2.getY().toString(16))
  })
  
  it('should match solidity implementation (baseScalarMult)', async function() {
    var randomNumber = Math.floor(Math.random() * 1000)
    var instance = await EC.deployed()
    var solidityP = await instance.libScalarBaseMult(randomNumber)
    var ecurveP = ec.curve.g.mul(randomNumber)
    assert.equal(solidityP[0].toString(16), ecurveP.getX().toString(16))
    assert.equal(solidityP[1].toString(16), ecurveP.getY().toString(16))
  })


})
