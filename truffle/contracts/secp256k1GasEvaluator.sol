pragma solidity ^0.4.24;

import './secp256k1.sol';

contract secp256k1GasEvaluator is secp256k1 {
  event Log(string logString);
  
  function evaluatePointAdd(uint256[2] a, uint256[2] b) public
    returns (uint256[2])
  {
    return pointAdd(a, b);
  }

}