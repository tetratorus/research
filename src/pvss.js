const Elliptic = require('elliptic').ec
const ec = new Elliptic('secp256k1')
const BN = require('bn.js')
const keccak256 = require('../utils/keccak256.js')
const random = require('../utils/random')

const errorTooFewShares = new Error("not enough shares to recover secret")
const errorDifferentLengths = new Error("inputs of different lengths")
const errorEncVerification = new Error("verification of encrypted share failed")
const errorDecVerification = new Error("verification of decrypted share failed")

const FIELD_ORDER = new BN('fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f', 16)

const nodeList = [] // list of public keys
const nodeSecrets = []
const nodes = 21
const threshold = 11
for (let i = 0; i < 21; i++) {
  let rand = random(32)
  nodeSecrets.push(rand)
  nodeList.push(ec.curve.g.mul(rand))
}

const secret = random(32) // shared secret

function createPriPoly(curve, threshold, secret) {
  let coeffs = []
  coeffs.push(secret)
  for (let i = 1; i < threshold; i++) {
    coeffs.push(random(32))
  }
  return coeffs // returns list of random coeffecients
}

function polyMul(pCoeffs, qCoeffs) {
  let d1 = pCoeffs.length - 1
  let d2 = qCoeffs.length - 1
  let newDegree = d1 + d2
  let coeffs = []
  for (let i = 0; i < newDegree.length + 1; i++) {
    coeffs.push(new BN(0))
  }
  for (let j = 0; j < pCoeffs.length; j++) {
    for (let k = 0; k < qCoeffs.length; k++) {
      let tmp = pCoeffs[j].mul(qCoeffs[k])
      coeffs[i+j] = tmp.add(coeffs[i+j], tmp)
    }
  }
  return coeffs
}

function evaluateAtPoly(coeffs, x) {
  var res = coeffs[0]
  for (let i = 1; i < coeffs.length; i++) {
    res = res.add(x.pow(new BN(i)).mul(coeffs[i]))
  }
  return res.umod(FIELD_ORDER)
}

function createEncShares(suite, ec.curve.g, nodeList, secret, threshold) {
  let encShares = []
  let priPoly = createPriPoly()
  let priShares = 
}