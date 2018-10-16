pragma solidity ^0.4.24;

import './secp256k1.sol';

contract secp256k1GasEvaluator is secp256k1 {
  event Log(string logString);
  
  function evaluatePointAdd(uint256[2] a, uint256[2] b) public
    returns (uint256[2])
  {
    return pointAdd(a, b);
  }

  function evaluateHackyScalarMult(uint256[2] p, uint256 s, uint256[] precomputes, uint256[2] memory indices) public
    returns (uint256[2])
  {
    return hackyScalarMult(p, s, precomputes, indices);
  }

  function evaluateInvMod(uint256 x) public
    returns (uint256)
  {
    return invMod(x);
  }

  function evaluateHackyInvMod(uint256 x, uint256[] precomputes, uint256[2] memory indices) public
    returns (uint256)
  {
    return hackyInvMod(x, precomputes, indices);
  }

  function evaluateHackyPointAdd(uint256[2] a, uint256[2] b, uint256[] precomputes, uint256[2] indices) public
    returns (uint256[2])
  {
    return hackyPointAdd(a, b, precomputes, indices); 
  }
}