pragma solidity ^0.4.24;

contract secp256k1 {
  uint256 public constant FIELD_ORDER = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;

  // Number of elements in the field (often called `q`)

  uint256 public constant GEN_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
  uint256 public constant CURVE_B = 7;
  uint256 public constant CURVE_A = 0;

  function genOrder() public pure
    returns (uint256)
  {
    return GEN_ORDER;
  }

  function fieldOrder() public pure
    returns (uint256)
  {
    return FIELD_ORDER;
  }

  function infinity() public pure
    returns (uint256[2])
  {
    return [uint256(0), uint256(0)];
  }
 
  function generator() public pure
    returns (uint256[2])
  {
    return [0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8];
  }

  function equal(uint256[2] a, uint256[2] b) public pure
    returns (bool)
  {
    return a[0] == b[0] && a[1] == b[1];
  }

  function negate(uint256[2] p) public pure
    returns (uint256[2])
  {
    if(p[0] == 0 && p[1] == 0) {
      return [uint256(0), uint256(0)];
    }
    // TODO: SubMod function?
    return [p[0], FIELD_ORDER - (p[1] % FIELD_ORDER)];
  }

  function hashToPoint(bytes32 s) public view
    returns (uint256[2])
  {
    uint256 beta = 0;
    uint256 y = 0;

    uint256 x = uint256(s) % FIELD_ORDER;

    while( true ) {
      (beta, y) = findYforX(x);

      // y^2 == beta
      if(beta == mulmod(y, y, FIELD_ORDER)) {
        return [x, y];
      }

      x = addmod(x, 1, FIELD_ORDER);
    }
  }

  function uintToPoint(uint256 x) public view
    returns (uint256[2])
  {
    uint256 beta = 0;
    uint256 y = 0;

    x = x % FIELD_ORDER;

    while( true ) {
      (beta, y) = findYforX(x);

      // y^2 == beta
      if(beta == mulmod(y, y, FIELD_ORDER)) {
        return [x, y];
      }

      x = addmod(x, 1, FIELD_ORDER);
    }
  }

  /*
    * Given X, find Y
    *
    *   where y = sqrt(x^3 + b)
    *
    * Returns: (x^3 + b), y
  **/
  function findYforX(uint256 x) public view
    returns (uint256, uint256)
  {
    // beta = (x^3 + b) % p
    uint256 beta = addmod(mulmod(mulmod(x, x, FIELD_ORDER), x, FIELD_ORDER), CURVE_B, FIELD_ORDER);

    // y^2 = x^3 + b
    // this acts like: y = sqrt(beta)
    uint256 y = expMod(beta, CURVE_A, FIELD_ORDER);

    return (beta, y);
  }

  function isInfinity(uint256[2] p) public pure
    returns (bool)
  {
    return p[0] == 0 && p[1] == 0;
  }

  /*
    * Verify if the X and Y coordinates represent a valid point on the curve
    *
    * Where the G1 curve is: x^2 = x^3 + b
  **/
  function isOnCurve(uint256[2] p) public pure
    returns (bool)
  {
    uint256 p_squared = mulmod(p[0], p[0], FIELD_ORDER);
    uint256 p_cubed = mulmod(p_squared, p[0], FIELD_ORDER);
    return addmod(p_cubed, CURVE_B, FIELD_ORDER) == mulmod(p[1], p[1], FIELD_ORDER);
  }

  function hackyScalarBaseMult(uint256 x, uint256[] points, uint256[1] memory index) public pure
    returns (uint256[2])
  {
    return hackyScalarMult(generator(), x, points, index);
  }

  /*
    * Multiply point by a scalar
  **/
  function hackyScalarMult(uint256[2] p, uint256 s, uint256[] points, uint256[1] memory index) public pure
    returns (uint256[2])
  {
    require(ecmulVerify(p, s, [points[index[0]], points[index[0]+1]]));
    index[0] = index[0] + 2;
    return ([points[index[0] - 2], points[index[0] - 1]]);
  }

  function expMod(uint256 base, uint256 exponent, uint256 modulus) public view
    returns (uint256 retval)
  {
    bool success;
    uint256[1] memory output;
    uint256[6] memory input;
    input[0] = 0x20;        // baseLen = new(big.Int).SetBytes(getData(input, 0, 32))
    input[1] = 0x20;        // expLen  = new(big.Int).SetBytes(getData(input, 32, 32))
    input[2] = 0x20;        // modLen  = new(big.Int).SetBytes(getData(input, 64, 32))
    input[3] = base;
    input[4] = exponent;
    input[5] = modulus;
    assembly {
      success := staticcall(sub(gas, 2000), 5, input, 0xc0, output, 0x20)
      // Use "invalid" to make gas estimation work
      switch success case 0 { invalid }
    }
    require(success);
    return output[0];
  }

  function ecmulVerify(uint256[2] a, uint256 scalar, uint256[2] q) public pure
    returns(bool)
  {
    uint256 m = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    address signer = ecrecover(0, a[1] % 2 != 0 ? 28 : 27, bytes32(a[0]), bytes32(mulmod(scalar, a[0], m)));
    address xyAddress = address(uint256(keccak256(abi.encodePacked(q[0], q[1]))) & 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
    return xyAddress == signer;
  }

  function publicKeyVerify(uint256 privKey, uint256[2] a) public pure
    returns(bool)
  {
    return ecmulVerify(
      [
        0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
        0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8
      ],
      privKey,
      a
    );
  }

  function uintToString(uint256 v) public pure returns (string str) {
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

  function verifySchnorrSignatureOnMessage(uint256[2] pub, string message, uint256 challenge, uint256 proof, uint256[] points, uint256[1] memory index) public pure returns (bool) {
    // y^e*g^s = r
    uint256[2] memory ye = hackyScalarMult(pub, challenge, points, index);
    uint256[2] memory gs = hackyScalarBaseMult(proof, points, index);
    uint256 projection = pointAdd(ye, gs)[0] % genOrder();
    return (challenge == uint256(keccak256(abi.encodePacked(message, uintToString(projection))))); // e = H(m, r)
  }

  function invmod(uint256 a, uint256 p) public pure returns (uint256) {
    if (a == 0 || a == p || p == 0)
      revert();
    if (a > p)
      a = a % p;
    int t1;
    int t2 = 1;
    uint256 r1 = p;
    uint256 r2 = a;
    uint256 q;
    while (r2 != 0) {
      q = r1 / r2;
      (t1, t2, r1, r2) = (t2, t1 - int(q) * t2, r2, r1 - q * r2);
    }
    if (t1 < 0)
      return (p - uint256(-t1));
    return uint256(t1);
  }

  function pointAdd(uint256[2] a, uint256[2] b) public pure returns (uint256[2] S) {
    if(a[0] == 0 && a[1] == 0)
        return b;
    if(b[0] == 0 && b[1] == 0)
        return a;
    uint256 p = FIELD_ORDER;
    if (a[0] == b[0]) {
      if (a[1] != b[1])
          return;
      else {
        return toZ1(_double([a[0], a[1], 1]), p);
      }
    }
    uint256[3] memory R;
    uint256 h = addmod(b[0], p - a[0], p);
    uint256 r = addmod(b[1], p - a[1], p);
    uint256 h2 = mulmod(h, h, p);
    uint256 h3 = mulmod(h2, h, p);
    uint256 Rx = addmod(mulmod(r, r, p), p - h3, p);
    Rx = addmod(Rx, p - mulmod(2, mulmod(a[0], h2, p), p), p);
    R[0] = Rx;
    R[1] = mulmod(r, addmod(mulmod(a[0], h2, p), p - Rx, p), p);
    R[1] = addmod(R[1], p - mulmod(a[1], h3, p), p);
    R[2] = mulmod(h, 1, p);
    return toZ1(R, p);
  }

  function _double(uint256[3] memory P) public pure returns (uint256[3] memory Q) {
    uint256 p = FIELD_ORDER;
    if (P[2] == 0)
      return;
    uint256 Px = P[0];
    uint256 Py = P[1];
    uint256 Py2 = mulmod(Py, Py, p);
    uint256 s = mulmod(4, mulmod(Px, Py2, p), p);
    uint256 m = mulmod(3, mulmod(Px, Px, p), p);
    uint256 Qx = addmod(mulmod(m, m, p), p - addmod(s, s, p), p);
    Q[0] = Qx;
    Q[1] = addmod(mulmod(m, addmod(s, p - Qx, p), p), p - mulmod(8, mulmod(Py2, Py2, p), p), p);
    Q[2] = mulmod(2, mulmod(Py, P[2], p), p);
  }


  function toZ1(uint[3] PJ, uint prime) public pure returns (uint256[2] R) {
    uint zInv = invmod(PJ[2], prime);
    uint zInv2 = mulmod(zInv, zInv, prime);
    R[0] = mulmod(PJ[0], zInv2, prime);
    R[1] = mulmod(PJ[1], mulmod(zInv, zInv2, prime), prime);
  }

}