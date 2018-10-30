var Elliptic = require('elliptic').ec
var ec = new Elliptic('secp256k1')
var BN = require('bn.js')
var keccak256 = require('../utils/keccak256.js')
var random = require('../utils/random.js')(ec)

var lagrange = {}
lagrange.interpolation = function (shares, shareIndex) {
  if (shares.length != shareIndex.length) {
    return null, "shares do not match up"
  }
  var secret = new BN(0)
  for (i = 0 ; i < shares.length; i ++) {
    var upper = new BN(1)
    var lower = new BN(1)
    for (j= 0; j < shares.length; j ++) {
      if (i != j) {
        upper = upper.mul(shareIndex[j].neg())
        upper = upper.umod(ec.curve.n)

        temp = shareIndex[i].sub(shareIndex[j])
        temp = temp.umod(ec.curve.n)
        lower = lower.mul(temp).umod(ec.curve.n)
      }  
    }
    // var privInv = ec.curve.n.sub(priv).umod(ec.curve.n) // note: inverse is using n
    // var y = ec.curve.g.mul(privInv)
    // var red = BN.red(ec.curve.n);
    // var lowerRed = lower.toRed(red)
    // var invRed = lowerRed.redInvm()
    // var inv = invRed.fromRed()
    // var inv = ec.curve.n.sub(lower).umod(ec.curve.n)
    delta = upper.mul(lower.invm(ec.curve.n)).umod(ec.curve.n)
    delta = delta.mul(shares[i]).umod(ec.curve.n)
    
    secret = secret.add(delta)
  }
  return secret.umod(ec.curve.n)
}

lagrange.newPolynomial = function (secret, threshold) {
  var coeff = []
  coeff[0] = secret
  for (i = 1; i < threshold; i ++) {
    coeff[i] = random(32).umod(ec.curve.n)
  }
  return coeff
}

lagrange.polyEval = function(coeff, noOfPoints) {
  var values = []
  for (i = 1; i < noOfPoints + 1; i++) {
    var oneVal = coeff[0]
    for (j = 1; j < coeff.length; j++) {
      temp = new BN(i)
      temp = temp.pow(new BN(j)) 
      oneVal = oneVal.add(coeff[j].mul(temp))
      oneVal = oneVal.umod(ec.curve.n)
    }
    values.push(oneVal)
  }
  return values
}

module.exports = lagrange
// var coeff = lagrange.newPolynomial(random(32).umod(ec.curve.n), 3)
// console.log(coeff)
// var points = lagrange.polyEval(coeff, 3)
// console.log(points)
// var shareIndex = []
// shareIndex.push(new BN(1))
// shareIndex.push(new BN(2))
// shareIndex.push(new BN(3))

// console.log(lagrange.interpolation(points, shareIndex))
