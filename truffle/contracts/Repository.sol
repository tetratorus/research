pragma solidity ^0.4.24;

import "./EC.sol";
import "./BytesLib.sol";
import {altbn128 as Curve} from "./altbn128.sol";
import {Strings as strings} from "./strings.sol";
import "./strings.sol";


contract Repository is EC {
  using BytesLib for bytes;
  using Curve for Curve.Point;
  using strings for string;

  struct Topic {
    bytes32[] sources;
    bytes question;
    uint256 deposit;
  }

  struct MCQAnswer {
    uint256 k;
    uint256[] elligibleE;
    uint256 pubKx;
  }

  mapping(bytes32 => Topic) topicStore;
  mapping(bytes32 => mapping(address => uint256)) topicKLog;
  mapping(bytes32 => mapping(address => uint256[])) topicEligibleE;
  mapping(bytes32 => mapping(address => MCQAnswer)) answerLog;
  uint256 topicNonce = 0;

  event TopicRegistered(bytes32 topicHash);
  event AddressRegistered(bytes32 topicHash, address _address, uint256 k);
  event Answer(bytes32 topicHash, uint256 pubKx, uint256 e); 

  constructor() public {

  }

  function viewRegistrationK(bytes32 _topicHash, address _addressToCheck) view public returns (uint256) {
    return answerLog[_topicHash][_addressToCheck].k;
  }

  function viewRegistrationPubK(bytes32 _topicHash, address _addressToCheck) view public returns (uint256) {
    return answerLog[_topicHash][_addressToCheck].pubKx;
  }

  function viewQuestion(bytes32 _topicHash) view public returns(bytes) {
    return topicStore[_topicHash].question;
  }

  function viewSoures(bytes32 _topicHash) view public returns(bytes32[]) {
    return topicStore[_topicHash].sources;
  }

  function registerTopic(bytes32[] _sources, bytes _question) payable public returns (bytes32) {
    //create Topic hash
    bytes memory strToBeHashed = "";
    for (uint256 i = 0; i < _sources.length; i++) {
      strToBeHashed = strToBeHashed.concat(abi.encodePacked(_sources[i]));
    }
    strToBeHashed = strToBeHashed.concat(_question);
    //nonce to ensure uniq-ness
    strToBeHashed = strToBeHashed.concat(uint256ToBytes(topicNonce));
    bytes32 topicHash = keccak256(strToBeHashed);
    //store topic with hash
    topicStore[topicHash] = Topic({sources: _sources, question: _question, deposit: msg.value});
    topicNonce ++;
    emit TopicRegistered(topicHash);
    return topicHash;
  }

  event Trace(bytes32 i);
  event Trace2(string i);
  event Trace3(bool i);

  //TODO: decide on bytes32/ using just strings everywhere
  function registerAddressToTopic(string _topicHash, string _pubKx, uint256[] _Rx, uint256[] _Ry, uint256[] _h, uint256[] _pubX, uint256[] _pubY, uint256 _sigma, uint256 _k) public {
    //message should refer to topicHash
    string memory _message = strings.concat(_topicHash.toSlice(), _pubKx.toSlice());
    bytes32 topicHashBytes32 = bytesToBytes32(fromHex(_topicHash), 0);
    uint256 pubKUint256 = fromHex(_pubKx).toUint(0);
    bytes32[] memory sources = topicStore[topicHashBytes32].sources;

    //pubKs should refer to stored sources (in the right order);
    for(uint256 i = 0; i < sources.length; i++) {
      //TODO: do we need to check both X and Y? 
      require(bytes32(_pubX[i]) == sources[i]);
    }

    //should be legit ring sig
    require(verifySchnorrRingSignature(_message, _Rx, _Ry, _h, _pubX, _pubY, _sigma));
    //whitelist sender and commit k
    //TODO: is storing k and r cheaper? or working with, opssibly create k randomly in solidity
    answerLog[topicHashBytes32][msg.sender] = MCQAnswer({pubKx: pubKUint256, k: _k, elligibleE: new uint[](0)});

    emit AddressRegistered(topicHashBytes32, msg.sender, _k);
  }


  //TODO: make only publisher
  function commitMCQ(bytes32 _topicHash, address _source, uint256[] _e) public {
    require(answerLog[_topicHash][_source].k != 0);
    answerLog[_topicHash][_source].elligibleE = _e;
  }

  function answerMCQ(bytes32 _topicHash, address _source, uint256 pubKy, uint256 _e, uint256 _s) public {
    MCQAnswer memory answer = answerLog[_topicHash][_source];
    uint256 X; 
    uint256 Y; 
    (X,Y) = libScalarBaseMult(answer.k);
    require(verifySchnorrSignature(answer.pubKx, pubKy, X, _e, _s));
    emit Answer(_topicHash, answer.pubKx, _e);
  }

  //UTILS
  // Nick Johnson https://ethereum.stackexchange.com/questions/4170/how-to-convert-a-uint-to-bytes-in-solidity
  function uint256ToBytes(uint256 x) internal pure returns (bytes b) {
    b = new bytes(32);
    assembly { mstore(add(b, 32), x) }
  }

  function bytesToBytes32(bytes b, uint offset) private pure returns (bytes32) {
    bytes32 out;
    for (uint i = 0; i < 32; i++) {
      out |= bytes32(b[offset + i] & 0xFF) >> (i * 8);
    }
    return out;
  }

  function stringToBytes32(string memory source) private pure returns (bytes32 result) {
    bytes memory tempEmptyStringTest = bytes(source);
    if (tempEmptyStringTest.length == 0) {
        return 0x0;
    }
    assembly {
        result := mload(add(source, 32))
    }
}

  // Tjaden Hess https://ethereum.stackexchange.com/questions/884/how-to-convert-an-address-to-bytes-in-solidity
  function addressToBytes(address a) internal pure returns (bytes b) {
    assembly {
        let m := mload(0x40)
        mstore(add(m, 20), xor(0x140000000000000000000000000000000000000000, a))
        mstore(0x40, add(m, 52))
        b := m
    }
  }

  // Convert an hexadecimal character to their value
  function fromHexChar(uint c) public pure returns (uint) {
    if (byte(c) >= byte('0') && byte(c) <= byte('9')) {
        return c - uint(byte('0'));
    }
    if (byte(c) >= byte('a') && byte(c) <= byte('f')) {
        return 10 + c - uint(byte('a'));
    }
    if (byte(c) >= byte('A') && byte(c) <= byte('F')) {
        return 10 + c - uint(byte('A'));
    }
  }

  function fromHex(string s) public pure returns (bytes) {
    bytes memory ss = bytes(s);
    require(ss.length%2 == 0); // length must be even
    bytes memory r = new bytes(ss.length/2);
    for (uint i=0; i<ss.length/2; ++i) {
        r[i] = byte(fromHexChar(uint(ss[2*i])) * 16 +
                    fromHexChar(uint(ss[2*i+1])));
    }
    return r;
}

}