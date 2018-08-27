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
var schnorrBlindSig = require('../../src/schnorrBlindSignature.js');

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
    var tempKeyPair = schnorrRingSig.randomKeys(1)[0]
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
    var ringSigMsg = topicHash.slice(2) + tempKeyPair.pubK.getX().toString(16,64);

    var ringSig = schnorrRingSig.sign(pubKCurve, keyPair, ringSigMsg)
    var kr = schnorrBlindSig.generateCommitment();

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
      tempKeyPair.pubK.getX().toString(16,64),
      Rx,
      Ry,
      h,
      pubX,
      pubY,
      "0x" + ringSig.sigma.umod(ec.curve.n).toString(16,64),
      "0x" + kr.k.umod(ec.curve.n).toString(16,64)
    )

    result = await repository.viewRegistrationK(topicHash, accounts[0]);
    assert.equal(!result.eq(0), schnorrRingSig.verify(ringSigMsg, ringSig.R, ringSig.h, pubKCurve, ringSig.sigma));
    result = await repository.viewRegistrationPubK(topicHash, accounts[0]);
    assert(result.eq(tempKeyPair.pubK.getX()));
  })

  it("should be able to commitMCQ()", async function () {
    var keys = schnorrRingSig.randomKeys(2)
    var keyPair = keys[0];
    var tempKeyPair = schnorrRingSig.randomKeys(1)[0]
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
    var ringSigMsg = topicHash.slice(2) + tempKeyPair.pubK.getX().toString(16,64);

    var ringSig = schnorrRingSig.sign(pubKCurve, keyPair, ringSigMsg)
    var kr = schnorrBlindSig.generateCommitment();

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
      tempKeyPair.pubK.getX().toString(16,64),
      Rx,
      Ry,
      h,
      pubX,
      pubY,
      "0x" + ringSig.sigma.umod(ec.curve.n).toString(16,64),
      "0x" + kr.k.umod(ec.curve.n).toString(16,64)
    )

    result = await repository.viewRegistrationK(topicHash, accounts[0]);
    assert.equal(!result.eq(0), schnorrRingSig.verify(ringSigMsg, ringSig.R, ringSig.h, pubKCurve, ringSig.sigma))
    result = await repository.viewRegistrationPubK(topicHash, accounts[0]);
    assert(result.eq(tempKeyPair.pubK.getX()));

    var elligibleE = [];
    var actualE = [];
    var answers = ["a","b","c"];
    answers.forEach(value => {
      var blindCommitment = schnorrBlindSig.generateBlindingCommitment(value, kr.r, tempKeyPair.pubK);
      actualE.push(blindCommitment.e);
      elligibleE.push("0x" + blindCommitment.e.toString(16,64));
    })
    result = await repository.commitMCQ(topicHash, accounts[0], elligibleE);
    
    var blindSig = schnorrBlindSig.sign(answers[0], tempKeyPair.privK, actualE[0], kr.k)
    result = await repository.answerMCQ(
      topicHash,
      accounts[0],
      "0x" + tempKeyPair.pubK.getY().toString(16,64),
      elligibleE[0], 
      "0x" + blindSig.s.toString(16,64) 
    );
    assert(result.logs[0].args.e.eq(actualE[0]));

  })
  
}) 