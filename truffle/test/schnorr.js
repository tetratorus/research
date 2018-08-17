var bitcore = require('bitcore-lib')
var elliptic = require('ec-altbn128').ec
var ec = new elliptic('altbn128')
var ECIES = require('bitcore-ecies')()
var BN = require('bn.js')
var EC = artifacts.require('EC')
var crypto = require('crypto')
var createKeccakHash = require('keccak')

function keccak256(inp){
  return createKeccakHash('keccak256').update(inp.toString()).digest('hex')
}

function random(bytes){
  do {
      var k = new BN(crypto.randomBytes(bytes))
  } while (k.toString() === "0" || k.toString() === "1" || k.gcd(ec.curve.n).toString() !== "1")
  return k.umod(ec.curve.n)
}

contract('Schnorr Tests', function(accounts) {
  
  it('should sign and verify', function() {
    // generate
    var m = "this is a random message"
    var priv = random(32)
    var privInv = ec.curve.n.sub(priv).umod(ec.curve.n) // note: inverse is using n
    var y = ec.curve.g.mul(privInv)
    var k = random(32)
    var r = ec.curve.g.mul(k)
    var e = keccak256(m + r.getX().toString())
    var s = k.add(priv.mul(new BN(e, 16)))
    
    // verify
    assert.equal(e, keccak256(m + y.mul(new BN(e, 16)).add(ec.curve.g.mul(s)).getX().toString()))
  })

  it('should sign and verify on-chain', async function() {
    // generate
    var m = "this is a random message"
    var priv = random(32)
    var privInv = ec.curve.n.sub(priv).umod(ec.curve.n)
    var y = ec.curve.g.mul(privInv)
    var k = random(32)
    var r = ec.curve.g.mul(k)
    var e = keccak256(m + r.getX().toString())
    var s = k.add(priv.mul(new BN(e, 16))).umod(ec.curve.n)
    
    // verify
    var instance = await EC.deployed()
    var res = await instance.verifySchnorrSignatureOnMessage(
      '0x' + y.getX().toString(16, 64),
      '0x' + y.getY().toString(16, 64),
      m,
      '0x' + e.toString(16, 64),
      '0x' + s.toString(16, 64)
    )
    assert.equal(res, true)
  })

  it('should blind schnorr sign and verify', async function() {
    // generate params
    var m = "this is a random message"
    var priv = random(32)
    var privInv = ec.curve.n.sub(priv).umod(ec.curve.n)
    var y = ec.curve.g.mul(privInv)

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

    // sign
    var s = k.add(priv.mul(e)).umod(ec.curve.n)

    // verify blind schnorr
    assert.equal(ec.curve.g.mul(s).add(y.mul(e)).getX().toString(16, 64), r.getX().toString(16, 64))

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
    sprime = s.add(alpha).umod(ec.curve.n)

    // verify deblinded schnorr
    assert.equal(ec.curve.g.mul(sprime).add(y.mul(eprime)).getX().toString(16, 64), rprime.getX().toString(16, 64))

    // verify deblinded schnorr on-chain
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

  it('should schnorr ring sign and verify between two parties', function() {
    // generate params, where signer has index 0
    var priv0 = random(32)
    var priv0Inv = ec.curve.n.sub(priv0).umod(ec.curve.n)
    var y0 = ec.curve.g.mul(priv0Inv)
    var priv1 = random(32)
    var priv1Inv = ec.curve.n.sub(priv1).umod(ec.curve.n)
    var y1 = ec.curve.g.mul(priv1Inv)
    var a0 = random(32)
    var a1 = random(32)
    var R1 = ec.curve.g.mul(a1)
    var m = "this is a random message"
    var hmr1 = keccak256(m + R1.getX().toString())
    var hmr1Inv = ec.curve.n.sub(new BN(hmr1, 16)).umod(ec.curve.n)
    var R0 = ec.curve.g.mul(a0).add(y1.mul(new BN(hmr1, 16)))
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

  // it should encrypt blinding params
  // it should decrypt blinding params
  // it should allow source-expert simulated flow
  // it should ring sign?
  // it should designated verifier extend...?

})
