var bitcore = require('bitcore-lib')
var elliptic = require('ec-altbn128').ec
var ec = new elliptic('altbn128')
var ECIES = require('bitcore-ecies')()
var BN = require('bn.js')
var keccak256 = require('../utils/keccak256.js');
var random = require('../utils/random.js')(ec);

var schnorrRingSignature = {};

schnorrRingSignature.randomKeys = function(n) {
  var keys = [];
  for (var i = 0; i < n; i ++) {
    var privK = random(32);
    var privC = ec.curve.n.sub(privK).umod(ec.curve.n);
    var pubK = ec.curve.g.mul(privC);
    keys.push({pubK:pubK, privK:privK});
  }
  return keys
}

schnorrRingSignature.sign = function(publicKeys, keyPair, m) {
  if (publicKeys.length === 0) throw "need more then zero public keys";

  var keyPairIndex;
  publicKeys.forEach((value, index) => {
    if (keyPair.pubK.getX().toString(16, 64) === value.getX().toString(16,64)) {
      keyPairIndex = index;
    }
  })

  var a = []; //array of a1...an
  for (var i = 0; i < publicKeys.length; i++) {
    var tempa = random(32);
    var duplicateExists = false;
    do {
      duplicateExists = false;
      a.forEach(value => {
        if (value.eq(tempa)) {
          duplicateExists = true;
          tempa = random(32);
        }
      })
    }
    while(duplicateExists);
    a[i] = tempa;
  }

  var R = [] //array of R1...Rn
  var hmr = [];//array of hmr0..hmrn
  for (var i = 0; i < publicKeys.length; i++) {
    if (keyPairIndex !== i) {
      R[i] = ec.curve.g.mul(a[i]);
      hmr[i] = keccak256(m + R[i].getX().toString())
    }
  }

  var pairwiseNotDistinct = true;
  do {
    pairwiseNotDistinct = false;
    var Rs = ec.curve.g.mul(a[keyPairIndex]);
    for (var i = 0; i < publicKeys.length; i++) {
      if (keyPairIndex !== i) {
        Rs = Rs.add(publicKeys[i].mul(new BN(hmr[i], 16)));
      }
    }
    R.forEach(value => {
      if (value.getX().toString(16,64) === (Rs.getX().toString(16,64))) {
        pairwiseNotDistinct = true;
        a[keyPairIndex] = random(32);
      }
    })
    if (Rs.getX().toString() === "1") pairwiseNotDistinct = true;
    
    if(pairwiseNotDistinct === false) {
      R[keyPairIndex] = Rs //set Rs in R
    }
  } while (pairwiseNotDistinct);

  var hmrs = keccak256(m + R[keyPairIndex].getX().toString());
  hmr[keyPairIndex] = hmrs;
  var sigma = keyPair.privK.mul(new BN(hmrs, 16));
  for (var i = 0; i < publicKeys.length; i++) {
    sigma = sigma.add(a[i]);
  }

  return {m:m, R: R, h:hmr, sigma:sigma};
}

schnorrRingSignature.verify = function (m, R, h, pubK, sigma) {
  var lhs = ec.curve.g.mul(sigma);
  var rhs = R[0];
  for (var i = 1; i < R.length; i ++) {
    rhs = rhs.add(R[i]);
  }
  for (var i = 0; i < R.length; i++) {
    rhs = rhs.add(pubK[i].mul(ec.curve.n.sub(new BN(h[i], 16)).umod(ec.curve.n)));
  }
  //verification sigma test
  var firstTest = lhs.getX().toString(16, 64) === rhs.getX().toString(16, 64);
  //check if all h = H(m+ R);
  var secondTest = true;
  for (var i = 0; i < R.length; i ++) {
    if (h[i] !== keccak256(m + R[i].getX().toString())) secondTest = false;
  }

  return firstTest && secondTest;
}

module.exports = schnorrRingSignature;
