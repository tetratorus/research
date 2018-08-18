// // const schnorr = require('schnorr')
// const elliptic = require('ec-altbn128').ec
// const ec = new elliptic('altbn128')
// const BN = require('bn.js')
// const crypto = require('crypto')
// const createKeccakHash = require('keccak')

// /*
// WIP
// This implements AOS 1-out-of-n ring signature which require only `n+1`
// scalars to validate in addition to the `n` public keys.

// ''Intuitively, this scheme is a ring of Schnorr signatures where each
// challenge is taken from the previous step. Indeed, it is the Schnorr
// signature scheme where n=1''

// For more information, see:

// - https://www.iacr.org/cryptodb/archive/2002/ASIACRYPT/50/50.pdf

// */

// function keccak256 (inp) {
//   return createKeccakHash('keccak256').update(inp.toString()).digest('hex')
// }

// function random (bytes) {
//   do {
//     var k = new BN(crypto.randomBytes(bytes))
//   } while (k.toString() == '0' && k.gcd(ec.curve.n).toString() != '1')
//   return k
// }

// var aosRingRandKeys = function (n) {
//   var keys = []
//   for (var i = 0; i < n; i++) {
//     var privK = random(32)
//     var pubK = ec.curve.g.mul(privC)
//     keys.push({pubK: pubK, privK: privK})
//   }
//   return keys
// }

// var aosSign = function (publicKeys, keyPair, tees, alpha, message) {
//   if (publicKeys.length === 0) throw 'need more then zero public keys'

//   // double check this
//   message = message || keccak256('insert something random')
//   var keyPairIndex = publicKeys.indexOf(keyPair.pubK)

//   if (tees === undefined) {
//     var tees = []
//     for (var i = 0; i < publicKeys.length; i++) {
//       tees.push(random(32))
//     }
//   }

//   var cees = []
//   for (var i = 0; i < publicKeys.length; i++) {
//     cees.push(0)
//   }

//   alpha = alpha || random(32)

//   var i = keyPairIndex
//   var n = 0
//   while (n < publicKeys.length) {
//     index = i % publicKeys.length
//     var c = (n === 0) ? alpha : cees[index - 1]
//   }
// }
