/* global assert, contract, it */
var Elliptic = require('ec-altbn128').ec
var ec = new Elliptic('altbn128')
var BN = require('bn.js')
var EC = artifacts.require('EC')
var Repository = artifacts.require('Repository')


var keccak256 = require('../../utils/keccak256.js')
var random = require('../../utils/random.js')(ec)
var schnorr = require('../../src/schnorr.js')
var schnorrRingSig = require('../../src/schnorrRingSignature.js');

contract("Basic question flow", async function (accounts) {

  beforeEach(async function () {
    repository = await Repository.new();
    ECContract = await EC.new();
  })

  it("should registerTopic()", async function () {
    var keys = schnorrRingSig.randomKeys(2)
    var keyPair = keys[0];
    var pubKSol = [];
    var pubKCurve = [];
    var deposit = 1000;
    keys.forEach(value => {
      pubKSol.push("0x" + value.pubK.getX().toString(16,64))
    })
    var question = "how blublu are you?"
    var result = await repository.registerTopic(pubKSol, question, {value:deposit})
    
    var topicHash = result.receipt.logs[0].data;
    
    result = await repository.viewQuestion(topicHash);
    assert(result.length > 2);
  })

  it("should be able to registerAddressToTopic()", async function () {
    var keys = schnorrRingSig.randomKeys(2)
    var keyPair = keys[0];
    var pubKSol = [];
    var pubKCurve = [];
    var deposit = 1000;
    keys.forEach(value => {
      pubKSol.push("0x" + value.pubK.getX().toString(16,64))
      pubKCurve.push(value.pubK)
    })
    var question = "how blublu are you?"
    var result = await repository.registerTopic(pubKSol, question, {value:deposit})
    
    var topicHash = result.receipt.logs[0].data;

    var ringSig = schnorrRingSig.sign(pubKCurve, keyPair, topicHash.slice(2))
    
    // test on-chain verificationo
    var Rx = []
    var Ry = []
    var pubX = [];
    var pubY = [];
    var h = [];
    for (var i = 0; i < ringSig.R.length; i++) {
      Rx.push("0x" + ringSig.R[i].getX().toString(16,64))
      Ry.push("0x" + ringSig.R[i].getY().toString(16,64))
      h.push("0x" + ringSig.h[i]);
      pubX.push("0x" + pubKCurve[i].getX().toString(16,64));
      pubY.push("0x" + pubKCurve[i].getY().toString(16,64));
    }
    result = await repository.registerAddressToTopic(
      topicHash.slice(2),
      Rx,
      Ry,
      h,
      pubX,
      pubY,
      "0x" + ringSig.sigma.umod(ec.curve.n).toString(16,64)
    )

    result = await repository.viewRegistration(topicHash, accounts[0]);
    assert.equal(result, schnorrRingSig.verify(topicHash.slice(2), ringSig.R, ringSig.h, pubKCurve, ringSig.sigma));
  })

}) 