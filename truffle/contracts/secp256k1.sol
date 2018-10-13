pragma solidity ^0.4.19;

library altbn128 {
    uint256 internal constant FIELD_ORDER = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;

    // Number of elements in the field (often called `q`)

    uint256 internal constant GEN_ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
    uint256 internal constant CURVE_B = 7;
    uint256 internal constant CURVE_A = 0;
    struct Point {
        uint256 X;
        uint256 Y;
    }

    function genOrder() internal pure returns (uint256) {
        return GEN_ORDER;
    }

    function fieldOrder() internal pure returns (uint256) {
        return FIELD_ORDER;
    }

    function infinity() internal pure returns (Point) {
        return Point(0, 0);
    }

    function generator() internal pure returns (Point) {
        return Point(0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798, 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8);
    }

    function equal(Point a, Point b) internal pure returns (bool) {
        return a.X == b.X && a.Y == b.Y;
    }

    /*
     * Return the negation of p, i.e. p.add(p.negate()) should be zero.
    **/
    function negate(Point p) internal pure returns (Point) {
        if(p.X == 0 && p.Y == 0) {
            return Point(0, 0);
        }
        // TODO: SubMod function?
        return Point(p.X, FIELD_ORDER - (p.Y % FIELD_ORDER));
    }

    /*
     * Using a hashed value as the initial starting X point, find the
     * nearest (X,Y) point on the curve. The input must be hashed first.
     *
     * Example:
     *
     *   hashToPoint(sha256("hello world"))
     *
     * XXX: this isn't constant time!
     *
     * This implements the try-and-increment method of hashing a scalar
     * into a curve point. For more information see:
     *
     *  - https://iacr.org/archive/crypto2009/56770300/56770300.pdf
     *    How to Hash into Elliptic Curves
     *
     *  - https://www.normalesup.org/~tibouchi/papers/bnhash-scis.pdf
     *    A Note on Hashing to BN Curves
    **/
    function hashToPoint(bytes32 s) internal view returns (Point) {
        uint256 beta = 0;
        uint256 y = 0;

        // XXX: Gen Order (n) or Field Order (p) ?
        // Using FIELD_ORDER seems to match elliptic's implementation
        uint256 x = uint256(s) % FIELD_ORDER;

        while( true ) {
            (beta, y) = findYforX(x);

            // y^2 == beta
            if(beta == mulmod(y, y, FIELD_ORDER)) {
                return Point(x, y);
            }

            x = addmod(x, 1, FIELD_ORDER);
        }
    }

    function uintToPoint(uint x) internal view returns (Point) {
        uint256 beta = 0;
        uint256 y = 0;

        // XXX: Gen Order (n) or Field Order (p) ?
        // Using FIELD_ORDER seems to match elliptic's implementation
        x = x % FIELD_ORDER;

        while( true ) {
            (beta, y) = findYforX(x);

            // y^2 == beta
            if(beta == mulmod(y, y, FIELD_ORDER)) {
                return Point(x, y);
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
    function findYforX(uint256 x) internal view returns (uint256, uint256) {
        // beta = (x^3 + b) % p
        uint256 beta = addmod(mulmod(mulmod(x, x, FIELD_ORDER), x, FIELD_ORDER), CURVE_B, FIELD_ORDER);

        // y^2 = x^3 + b
        // this acts like: y = sqrt(beta)
        uint256 y = expMod(beta, CURVE_A, FIELD_ORDER);

        return (beta, y);
    }

    function isInfinity(Point p) internal pure returns (bool) {
        return p.X == 0 && p.Y == 0;
    }

    /*
     * Verify if the X and Y coordinates represent a valid Point on the Curve
     *
     * Where the G1 curve is: x^2 = x^3 + b
    **/
    function isOnCurve(Point p) internal pure returns (bool) {
        uint256 p_squared = mulmod(p.X, p.X, FIELD_ORDER);
        uint256 p_cubed = mulmod(p_squared, p.X, FIELD_ORDER);
        return addmod(p_cubed, CURVE_B, FIELD_ORDER) == mulmod(p.Y, p.Y, FIELD_ORDER);
    }

    function scalarBaseMult(uint256) internal pure returns (Point) {
      require(false, "use hackyScalarBaseMult for secp256k1");
    }

    /*
     * Multiply the curve generator by a scalar
    **/
    function hackyScalarBaseMult(uint256 x, uint256[] points, uint256 _index) internal pure returns (Point, uint256) {
        return hackyScalarMult(generator(), x, points, _index);
    }

    /*
     * Sum of two points
    **/
    function pointAdd(Point p1, Point p2) internal pure returns (Point)
    {
        uint256 rx;
        uint256 ry;
        (rx, ry) = ((  addmod( mulmod(p2.Y, p1.X , GEN_ORDER) ,
                              mulmod(p2.X, p1.Y , GEN_ORDER),
                              GEN_ORDER),
                      mulmod(p1.Y, p2.Y , GEN_ORDER)
                    ));
        return Point(rx, ry);
    }

    function scalarMult(Point, uint256) internal pure returns (Point) {
      require(false, "use hackyScalarMult for secp256k1");
    }

    /*
     * Multiply point by a scalar
    **/
    function hackyScalarMult(Point p, uint256 s, uint256[] points, uint256 _index) internal pure returns (Point, uint256) {
        assert(ecmulVerify(p.X, p.Y, s, points[_index], points[_index + 1]));
        return (Point({X: points[_index], Y: points[_index + 1]}), _index + 2);
    }

    function expMod(uint256 base, uint256 exponent, uint256 modulus)
        internal view returns (uint256 retval)
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

    function ecmulVerify(uint256 x1, uint256 y1, uint256 scalar, uint256 qx, uint256 qy) public pure
        returns(bool)
    {
        uint256 m = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        address signer = ecrecover(0, y1 % 2 != 0 ? 28 : 27, bytes32(x1), bytes32(mulmod(scalar, x1, m)));
        address xyAddress = address(uint256(keccak256(abi.encodePacked(qx, qy))) & 0x00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF);
        return xyAddress == signer;
    }

    function publicKeyVerify(uint256 privKey, uint256 x, uint256 y) public pure
        returns(bool)
    {
        uint256 gx = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798;
        uint256 gy = 0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8;
        return ecmulVerify(gx, gy, privKey, x, y);
    }
}