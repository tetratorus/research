pragma solidity ^0.4.24;

import {BlindSchnorr} from './BlindSchnorr.sol';

contract Repository {

  struct Topic {
    address[] sources;
    string question;
    
  }

  constructor() public {

  }

  function registerTopic(address[] sources, string question) payable public returns (bool) {
    return false;
  }

}