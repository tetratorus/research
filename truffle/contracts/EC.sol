pragma solidity ^0.4.24;

import {strings} from './strings.sol';
import {altbn128 as Curve} from './altbn128.sol';

contract EC {
  using Curve for Curve.Point;
  using strings for string;

  function libGenOrder() public pure returns (uint256) {
    return Curve.genOrder();
  }

  function libFieldOrder() public pure returns (uint256) {
    return Curve.fieldOrder();
  }

  function libInfinity() public pure returns (uint256, uint256) {
    Curve.Point memory res = Curve.infinity();
    return (res.X, res.Y);
  }

  function libGenerator() public pure returns (uint256, uint256) {
    Curve.Point memory res = Curve.generator();
    return (res.X, res.Y);
  }

  function libEqual(uint256 aX, uint256 aY, uint256 bX, uint256 bY) public pure returns (bool) {
    return Curve.equal(Curve.Point({X: aX, Y: aY}), Curve.Point({X: bX, Y: bY}));
  }

  function libNegate(uint256 aX, uint256 aY) public pure returns (uint256, uint256) {
    Curve.Point memory res = Curve.negate(Curve.Point({X: aX, Y: aY}));
    return (res.X, res.Y);
  }

  function libHashToPoint(bytes32 s) public view returns (uint256, uint256) {
    Curve.Point memory res = Curve.hashToPoint(s);
    return (res.X, res.Y);
  }

  function libUintToPoint(uint256 x) public view returns (uint256, uint256) {
    Curve.Point memory res = Curve.uintToPoint(x);
    return (res.X, res.Y);
  }

  function libFindYforX(uint256 x) public view returns (uint256, uint256) {
    return Curve.findYforX(x);
  }

  function libIsInfinity(uint256 aX, uint256 aY) public pure returns (bool) {
    return Curve.isInfinity(Curve.Point({X: aX, Y: aY}));
  } 

  function libIsOnCurve(uint256 aX, uint256 aY) public pure returns (bool) {
    return Curve.isOnCurve(Curve.Point({X: aX, Y: aY}));
  }

  function libScalarBaseMult(uint256 x) public view returns (uint256, uint256) {
    Curve.Point memory res = Curve.scalarMult(Curve.generator(), x);
    return (res.X, res.Y);
  }

  function libPointAdd(uint256 aX, uint256 aY, uint256 bX, uint256 bY) public view returns (uint256, uint256) {
    Curve.Point memory res = Curve.pointAdd(Curve.Point({X: aX, Y: aY}), Curve.Point({X: bX, Y: bY}));
    return (res.X, res.Y);
  }

  function libScalarMult(uint256 aX, uint256 aY, uint256 s) public view returns (uint256, uint256) {
    Curve.Point memory res = Curve.scalarMult(Curve.Point({X: aX, Y: aY}), s);
    return (res.X, res.Y);
  }

  function libExpMod(uint256 base, uint256 exponent, uint256 modulus) public view returns (uint256 retval) {
    return Curve.expMod(base, exponent, modulus);
  }
  
  // converts uint256 to string
  function uintToString(uint256 v) pure public returns (string str) {
    uint256 maxlength = 78;
    bytes memory reversed = new bytes(maxlength);
    uint256 i = 0;
    while (v != 0) {
      uint256 remainder = v % 10;
      v = v / 10;
      reversed[i++] = byte(48 + remainder);
    }
    bytes memory s = new bytes(i);
    for (uint256 j = 0; j < i; j++) {
      s[j] = reversed[i - 1 - j];
    }
    str = string(s);
  }

  function verifySchnorrSignatureOnMessage(uint256 pubX, uint256 pubY, string message, uint256 challenge, uint256 proof) view public returns (bool) {
    Curve.Point memory sum = Curve.pointAdd(Curve.Point({X: pubX, Y: pubY}).scalarMult(challenge), Curve.scalarBaseMult(proof)); // y^e*g^s = r
    uint256 projection = sum.X % Curve.genOrder();
    return (challenge == uint256(keccak256(abi.encodePacked(message,uintToString(projection))))); // e = H(m, r)
  }

  function verifySchnorrSignature(uint256 pubX, uint256 pubY, uint256 r, uint256 challenge, uint256 proof) view public returns (bool) {
    Curve.Point memory sum = Curve.pointAdd(Curve.Point({X: pubX, Y: pubY}).scalarMult(challenge), Curve.scalarBaseMult(proof)); // y^e*g^s = r
    uint256 projection = sum.X % Curve.genOrder();
    return (projection == r);
  }

/*
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
*/
  function verifySchnorrRingSignature(string message, uint256[] Rx, uint256[] Ry, uint256[] h, uint256[] pubX, uint256[] pubY, uint256 sigma) view public returns (bool) {
    Curve.Point memory lhs = Curve.scalarBaseMult(sigma);
    Curve.Point memory rhs = Curve.Point({X:Rx[0], Y: Ry[0]});
    for (uint256 i = 1; i < Rx.length; i ++) {
      rhs = rhs.pointAdd(Curve.Point({X:Rx[i], Y: Ry[i]}));
    }
    for (i = 0; i < Rx.length; i ++) {
      rhs = rhs.pointAdd(Curve.Point({X:pubX[i], Y:pubY[i]}).scalarMult(h[i]).negate());
    }
    bool firstTest = lhs.equal(rhs);
    bool secondTest = true;
    for (i = 0; i < Rx.length; i ++) {
      if (h[i] != uint256(keccak256(abi.encodePacked(message,uintToString(Rx[i]))))) {
        secondTest = false;
      }
    }
    return firstTest && secondTest;
  }
}
