var Elliptic = require('ec-altbn128').ec
var ec = new Elliptic('altbn128')
var BN = require('bn.js')
var keccak256 = require('../utils/keccak256.js')
var random = require('../utils/random.js')(ec)

var schnorrBlindSignature = {}



module.exports = schnorrBlindSignature;