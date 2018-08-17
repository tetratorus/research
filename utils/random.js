var BN = require('bn.js');
var crypto = require('crypto')

module.exports = (ec) => {
  return function random(bytes){
    do {
        var k = new BN(crypto.randomBytes(bytes))
    } while (k.toString() == "0" && k.gcd(ec.curve.n).toString() != "1")
    return k
  }
}
