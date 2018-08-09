pragma solidity ^0.4.24;

import {bn256g1 as Curve} from './bn256g1.sol';

library BlindSchnorr {
  using Curve for Curve.Point;

  // converts uint256 to string
  function uintToString(uint v) pure public returns (string str) {
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

  function verifySchnorrSignature(uint256 pubX, uint256 pubY, uint256 message, uint256 challenge, uint256 proof) view public {
    Curve.Point memory sum = Curve.pointAdd(Curve.Point({X: pubX, Y: pubY}).scalarMult(challenge), Curve.scalarBaseMult(proof)); // g^s*y^e = r
    uint256 projection = sum.X % Curve.genOrder();
    require(challenge == uint256(keccak256(abi.encodePacked(uintToString(message),uintToString(projection))))); // e = H(m, r)
  }
}