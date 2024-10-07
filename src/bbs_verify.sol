// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// https://github.com/tornadocash/tornado-core/blob/master/contracts/Verifier.sol
library Pairing {
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant T24 = 0x1000000000000000000000000000000000000000000000000;
    uint256 constant MASK24 = 0xffffffffffffffffffffffffffffffffffffffffffffffff;
    uint256 private constant A = 0;
    uint256 private constant B = 3;
    /// @notice Param Z for SVDW over E
    uint256 private constant Z = 1;
    /// @notice g(Z) where g(x) = x^3 + 3
    uint256 private constant C1 = 0x4;
    /// @notice -Z / 2 (mod N)
    uint256 private constant C2 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;
    /// @notice C3 = sqrt(-g(Z) * (3 * Z^2 + 4 * A)) (mod N)
    ///     and sgn0(C3) == 0
    uint256 private constant C3 = 0x16789af3a83522eb353c98fc6b36d713d5d8d1cc5dffffffa;
    /// @notice 4 * -g(Z) / (3 * Z^2 + 4 * A) (mod N)
    uint256 private constant C4 = 0x10216f7ba065e00de81ac1e7808072c9dd2b2385cd7b438469602eb24829a9bd;
    /// @notice (N - 1) / 2
    uint256 private constant C5 = 0x183227397098d014dc2822db40c0ac2ecbc0b548b438e5469e10460b6c3e7ea3;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint256[2] X;
        uint256[2] Y;
    }

    /*
    * @return The negation of p, i.e. p.plus(p.negate()) should be zero.
    */
    function negate(G1Point memory p) internal pure returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        if (p.X == 0 && p.Y == 0) {
            return G1Point(0, 0);
        } else {
            return G1Point(p.X, PRIME_Q - (p.Y % PRIME_Q));
        }
    }

    /*
    * @return r the sum of two points of G1
    */
    function plus(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }

        require(success, "pairing-add-failed");
    }

    /*
    * @return r the product of a point on G1 and a scalar, i.e.
    *         p == p.scalar_mul(1) and p.plus(p) == p.scalar_mul(2) for all
    *         points p.
    */
    function scalar_mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }
        require(success, "pairing-mul-failed");
    }

    /* @return The result of computing the pairing check
    *         e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    *         For example,
    *         pairing([P1(), P1().negate()], [P2(), P2()]) should return true.
    */
    function pairing(
        G1Point memory a1,
        G2Point memory a2,
        G1Point memory b1,
        G2Point memory b2,
        G1Point memory c1,
        G2Point memory c2
    ) internal view returns (bool) {
        G1Point[3] memory p1 = [a1, b1, c1];
        G2Point[3] memory p2 = [a2, b2, c2];

        uint256 inputSize = 18;
        uint256[] memory input = new uint256[](inputSize);

        for (uint256 i = 0; i < 3; i++) {
            uint256 j = i * 6;
            input[j + 0] = p1[i].X;
            input[j + 1] = p1[i].Y;
            input[j + 2] = p2[i].X[0];
            input[j + 3] = p2[i].X[1];
            input[j + 4] = p2[i].Y[0];
            input[j + 5] = p2[i].Y[1];
        }

        uint256[1] memory out;
        bool success;

        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success
            case 0 { invalid() }
        }

        require(success, "pairing-opcode-failed");

        return out[0] != 0;
    }

    function from_okm(bytes memory _msg) public pure returns (uint256) {
        uint256 z0;
        uint256 z1;
        uint256 a0;

        assembly {
            let p := add(_msg, 24)
            z1 := and(mload(p), MASK24)
            p := add(_msg, 48)
            z0 := and(mload(p), MASK24)
            a0 := addmod(mulmod(z1, T24, SNARK_SCALAR_FIELD), z0, SNARK_SCALAR_FIELD)
        }
        return a0;
    }

    // https://github.com/kilic/evmbls/blob/master/contracts/BLS.sol#L460
    // only for len_in_bytes = 48 or 96
    function expandMsg(bytes memory domain, bytes memory message, uint8 len_in_bytes)
        public
        pure
        returns (bytes memory)
    {
        uint256 t1 = domain.length;
        require(t1 < 256, "BLS: invalid domain length");

        uint256 t0 = message.length;
        bytes memory msg0 = new bytes(t1 + t0 + 64 + 4); // Buffer for the message
        bytes memory out = new bytes(48); // Output buffer

        // Create the initial message
        assembly {
            let p := add(msg0, 96)

            // Copy the message into msg0
            let z := 0
            for {} lt(z, t0) { z := add(z, 32) } { mstore(add(p, z), mload(add(message, add(z, 32)))) }
            p := add(p, t0)

            // Append fixed data
            mstore8(p, 0) // zero
            p := add(p, 1)
            mstore8(p, len_in_bytes)
            p := add(p, 1)
            mstore8(p, 0) // 0 byte
            p := add(p, 1)

            // Append domain length and copy the full domain
            for { let i := 0 } lt(i, t1) { i := add(i, 32) } { mstore(add(p, i), mload(add(domain, add(i, 32)))) }
            p := add(p, t1)
            mstore8(p, t1)
        }

        // Compute b0
        bytes32 b0 = sha256(msg0);
        bytes32 bi;
        uint256 newLength = t1 + 34;

        // Resize intermediate message
        assembly {
            mstore(msg0, newLength)
        }

        // Compute b1
        assembly {
            mstore(add(msg0, 32), b0)
            mstore8(add(msg0, 64), 1)
            for { let i := 0 } lt(i, t1) { i := add(i, 32) } {
                mstore(add(msg0, add(65, i)), mload(add(domain, add(i, 32))))
            }
            mstore8(add(msg0, add(65, t1)), t1)
        }

        bi = sha256(msg0);

        // Store b1
        assembly {
            mstore(add(out, 32), bi)
        }

        // Compute b2
        assembly {
            let t := xor(b0, bi)
            mstore(add(msg0, 32), t)
            mstore8(add(msg0, 64), 2)
            for { let i := 0 } lt(i, t1) { i := add(i, 32) } {
                mstore(add(msg0, add(65, i)), mload(add(domain, add(i, 32))))
            }
            mstore8(add(msg0, add(65, t1)), t1)
        }

        bi = sha256(msg0);

        // Store b2
        assembly {
            mstore(add(out, 64), bi)
        }

        if (len_in_bytes == 96) {
            // // b3

            // solium-disable-next-line security/no-inline-assembly
            assembly {
                let t := xor(b0, bi)
                mstore(add(msg0, 32), t)
                mstore8(add(msg0, 64), 3)
                mstore(add(msg0, 65), mload(add(domain, 32)))
                mstore8(add(msg0, add(t1, 65)), t1)
            }

            bi = sha256(msg0);

            // solium-disable-next-line security/no-inline-assembly
            assembly {
                mstore(add(out, 96), bi)
            }
        }
        return out;
    }

    /// @notice Hash to BN254 G1
    /// @param domain Domain separation tag
    /// @param message Message to hash
    /// @return Point in G1
    function hashToPoint(bytes memory domain, bytes memory message) public view returns (uint256[2] memory) {
        uint256[2] memory u = hashToField(domain, message);
        uint256[2] memory p0 = mapToPoint(u[0]);
        uint256[2] memory p1 = mapToPoint(u[1]);
        uint256[4] memory bnAddInput;
        bnAddInput[0] = p0[0];
        bnAddInput[1] = p0[1];
        bnAddInput[2] = p1[0];
        bnAddInput[3] = p1[1];
        bool success;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            success := staticcall(sub(gas(), 2000), 6, bnAddInput, 128, p0, 64)
        }
        require(success, "BN Add failed");
        return p0;
    }

    /// @notice Hash a message to the field
    /// @param domain Domain separation tag
    /// @param message Message to hash
    function hashToField(bytes memory domain, bytes memory message) internal pure returns (uint256[2] memory) {
        bytes memory _msg = expandMsg(domain, message, 96);
        uint256 u0;
        uint256 u1;
        uint256 a0;
        uint256 a1;
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let p := add(_msg, 24)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 48)
            u0 := and(mload(p), MASK24)
            a0 := addmod(mulmod(u1, T24, PRIME_Q), u0, PRIME_Q)
            p := add(_msg, 72)
            u1 := and(mload(p), MASK24)
            p := add(_msg, 96)
            u0 := and(mload(p), MASK24)
            a1 := addmod(mulmod(u1, T24, PRIME_Q), u0, PRIME_Q)
        }
        return [a0, a1];
    }

    /// @notice Map field element to E using SvdW
    /// @param u Field element to map
    /// @return p Point on curve
    function mapToPoint(uint256 u) internal view returns (uint256[2] memory p) {
        require(u < PRIME_Q, "invalid u");

        uint256 tv1 = mulmod(mulmod(u, u, PRIME_Q), C1, PRIME_Q);
        uint256 tv2 = addmod(1, tv1, PRIME_Q);
        tv1 = addmod(1, PRIME_Q - tv1, PRIME_Q);
        uint256 tv3 = inverse(mulmod(tv1, tv2, PRIME_Q));
        uint256 tv5 = mulmod(mulmod(mulmod(u, tv1, PRIME_Q), tv3, PRIME_Q), C3, PRIME_Q);
        uint256 x1 = addmod(C2, PRIME_Q - tv5, PRIME_Q);
        uint256 x2 = addmod(C2, tv5, PRIME_Q);
        uint256 tv7 = mulmod(tv2, tv2, PRIME_Q);
        uint256 tv8 = mulmod(tv7, tv3, PRIME_Q);
        uint256 x3 = addmod(Z, mulmod(C4, mulmod(tv8, tv8, PRIME_Q), PRIME_Q), PRIME_Q);

        bool hasRoot;
        uint256 gx;
        if (legendre(g(x1)) == 1) {
            p[0] = x1;
            gx = g(x1);
            (p[1], hasRoot) = sqrt(gx);
            require(hasRoot, "root not found");
        } else if (legendre(g(x2)) == 1) {
            p[0] = x2;
            gx = g(x2);
            (p[1], hasRoot) = sqrt(gx);
            require(hasRoot, "root not found");
        } else {
            p[0] = x3;
            gx = g(x3);
            (p[1], hasRoot) = sqrt(gx);
            require(hasRoot, "root not found");
        }
        if (sgn0(u) != sgn0(p[1])) {
            p[1] = PRIME_Q - p[1];
        }
    }

    /// @notice sqrt(xx) mod N
    /// @param xx Input
    function sqrt(uint256 xx) internal view returns (uint256 x, bool hasRoot) {
        x = expMod(xx, (PRIME_Q + 1) / 4, PRIME_Q);
        hasRoot = mulmod(x, x, PRIME_Q) == xx;
    }

    /// @notice g(x) = y^2 = x^3 + 3
    function g(uint256 x) private pure returns (uint256) {
        return addmod(mulmod(mulmod(x, x, PRIME_Q), x, PRIME_Q), B, PRIME_Q);
    }

    /// @notice https://datatracker.ietf.org/doc/html/rfc9380#name-the-sgn0-function
    function sgn0(uint256 x) private pure returns (uint256) {
        return x % 2;
    }

    /// @notice Compute Legendre symbol of u
    /// @param u Field element
    /// @return 1 if u is a quadratic residue, -1 if not, or 0 if u = 0 (mod p)
    function legendre(uint256 u) private view returns (int8) {
        uint256 x = modexpLegendre(u);
        if (x == PRIME_Q - 1) {
            return -1;
        }
        require(x == 0 || x == 1, "invalid Legendre symbol");
        return int8(int256(x));
    }

    /// @notice This is cheaper than an addchain for exponent (N-1)/2
    function modexpLegendre(uint256 u) private view returns (uint256 output) {
        bytes memory input = new bytes(192);
        bool success;
        assembly {
            let p := add(input, 32)
            mstore(p, 32) // len(u)
            p := add(p, 32)
            mstore(p, 32) // len(exp)
            p := add(p, 32)
            mstore(p, 32) // len(mod)
            p := add(p, 32)
            mstore(p, u) // u
            p := add(p, 32)
            mstore(p, C5) // (N-1)/2
            p := add(p, 32)
            mstore(p, PRIME_Q) // N

            success :=
                staticcall(
                    gas(),
                    5,
                    add(input, 32),
                    192,
                    0x00, // scratch space <- result
                    32
                )
            output := mload(0x00) // output <- result
        }
        require(success, "modexp-legendre-failed");
    }

    function inverse(uint256 a) internal view returns (uint256) {
        return expMod(a, PRIME_Q - 2, PRIME_Q);
    }

    function expMod(uint256 base, uint256 expo, uint256 modn) internal view returns (uint256 result) {
        bool success;
        assembly {
            let freemem := mload(0x40)
            mstore(freemem, 0x20) // Length of base
            mstore(add(freemem, 0x20), 0x20) // Length of exponent
            mstore(add(freemem, 0x40), 0x20) // Length of modulus
            mstore(add(freemem, 0x60), base) // Base
            mstore(add(freemem, 0x80), expo) // Exponent
            mstore(add(freemem, 0xa0), modn) // Modulus
            success := staticcall(sub(gas(), 2000), 0x05, freemem, 0xc0, freemem, 0x20)
            result := mload(freemem)
        }
        require(success, "Modular exponentiation failed");
    }
}

library BBS {
    using Pairing for *;

    /// generator of G1
    function BP1() internal pure returns (Pairing.G1Point memory) {
        return Pairing.G1Point(uint256(1), uint256(2));
    }

    /// generator of G2
    function BP2() internal pure returns (Pairing.G2Point memory) {
        return Pairing.G2Point(
            [
                uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
                uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781)
            ],
            [
                uint256(4082367875863433681332203403145435568316851327593401208105741076214120093531),
                uint256(8495653923123431417604973247489272438418190587263600148770280649306958101930)
            ]
        );
    }

    /// negation of generator of G2
    function BP2Negate() internal pure returns (Pairing.G2Point memory) {
        return Pairing.G2Point(
            [
                uint256(11559732032986387107991004021392285783925812861821192530917403151452391805634),
                uint256(10857046999023057135944570762232829481370756359578518086990519993285655852781)
            ],
            [
                uint256(17805874995975841540914202342111839520379459829704422454583296818431106115052),
                uint256(13392588948715843804641432497768002650278120570034223513918757245338268106653)
            ]
        );
    }

    // set of randomly sampled points from the G1 subgroup,
    // api_id = ciphersuite_id || "H2G_HM2S_"
    // CIPHERSUITE_ID: &[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_"
    function generators() internal pure returns (Pairing.G1Point[32] memory) {
        return [
            Pairing.G1Point(
                uint256(14209430103424996476411043444354935157416303663781110285074689873904795753579),
                uint256(3147027275750645911911115093446053376060701457126778782726080478608931158905)
            ),
            Pairing.G1Point(
                uint256(18913916542948759409282123705133431489605942222791445898569881277917683805334),
                uint256(9964355566330467396566861302551927237867357960133836848469875848519760373555)
            ),
            Pairing.G1Point(
                uint256(185200575564411050627786573152707464260358536178940607965586766573241335430),
                uint256(20714562299123241179680408685428291568578925534895622821325120283507303088322)
            ),
            Pairing.G1Point(
                uint256(19945759352355266083458953470321414674332324515980376150674039576634528755332),
                uint256(10005179287406799622370547568632167046698236365248773129362925468205477475873)
            ),
            Pairing.G1Point(
                uint256(3816539479643338944759298291464681192277983035912689733770494508811574555636),
                uint256(9012924080423984920394486479942110564432750124182663486569090223252260834673)
            ),
            Pairing.G1Point(
                uint256(5503641602689106148225048845214463777923510312174681209329424535855896891807),
                uint256(18855361233142251924515218778489732696262088712916182672274951798948646574614)
            ),
            Pairing.G1Point(
                uint256(5088124846464273193019221050625600521032734589946389224092190379437590154065),
                uint256(6416271221657758966414097734287184125694475293237914233597130674976569687078)
            ),
            Pairing.G1Point(
                uint256(20867680094384965415430814954750476939281108873463893726369574104505711531713),
                uint256(15313558072170142110042684335532264510504254431172157718827227546994512565063)
            ),
            Pairing.G1Point(
                uint256(13332179985482784038423999771784111532569533057023094804125481146734402475361),
                uint256(507680900152057301814896529335572438268974885744736678380170456761999333657)
            ),
            Pairing.G1Point(
                uint256(3045038804119001941107890165390844818828459912481507584096310983819098766879),
                uint256(16307964546335583308110698700729181159053069282356638653459401639088234344604)
            ),
            Pairing.G1Point(
                uint256(3559644071596397414057764249552229826405097815668910787154456861598728810278),
                uint256(4391779124995501673609867762113662836793492829364560881363073603626930655625)
            ),
            Pairing.G1Point(
                uint256(21653082138260604213309855567760806107492431734484035139700890716900599343303),
                uint256(239207695156865581144238151433636535046365967131086294199296695227941171770)
            ),
            Pairing.G1Point(
                uint256(19532594960074716982536287622079647052436395878182748669253163037560148413726),
                uint256(18814379304601867855783758127354011339568480498358817716656599066590420245147)
            ),
            Pairing.G1Point(
                uint256(5530277546553736393976250575755746872054185799592366955448004125627273921538),
                uint256(14721946721422657898818820528438663071615088950081190286666632558960619493411)
            ),
            Pairing.G1Point(
                uint256(5304174250557546383575733979460192076560718724266164035883159798186454330954),
                uint256(5132963744980611805030961216467932318707275791112663960754378443695070699332)
            ),
            Pairing.G1Point(
                uint256(18747176684043165020737413840763631299982680173696786910078949462642216569861),
                uint256(3184798469160958711549356257994962696015550939851038992100841134011307659561)
            ),
            Pairing.G1Point(
                uint256(11617367740317604325515897058722072091631998560749979862978584982439032934026),
                uint256(10714631081278637802267913792073836852277883847482354349547212697065685038978)
            ),
            Pairing.G1Point(
                uint256(10443739009275050855617151793639472164514116361986835336876949215494067786354),
                uint256(17533063143390745559313023645655309797015876324479214359854925928229546974170)
            ),
            Pairing.G1Point(
                uint256(18089487670226829519026544738090516690994653358523677206408472845446247967506),
                uint256(18790516992677456776407534266144705464194079495023452727799859724626037654413)
            ),
            Pairing.G1Point(
                uint256(15686787961755056545317135398414683826638785820078368032571700862736492626196),
                uint256(17002388742937219061233294192933098643630775184099574496912893206631623588296)
            ),
            Pairing.G1Point(
                uint256(1234793686678174125286055678852791020565513242367839254000047156928512479244),
                uint256(8023212426403815577423199953592544767025937384974745028980221040842561245129)
            ),
            Pairing.G1Point(
                uint256(12963386635172491742735929755803989093490296647313990230221027872454049928570),
                uint256(4679895864973218183807762557889565158165986742372502912132148020556720240834)
            ),
            Pairing.G1Point(
                uint256(3912185879860484366996197701758888492731463962797418423251438967978406709243),
                uint256(9337100572161988718489241756950779718727341085906578489198306529969355191073)
            ),
            Pairing.G1Point(
                uint256(19820260794974828351373124860128837608847907488815602797559456381519956658861),
                uint256(14143139697714912538622250020338763182931575630381740393807396079048113615040)
            ),
            Pairing.G1Point(
                uint256(13264853899440456693803942806358444107171743288228535282479477294125766698940),
                uint256(2307662363094877437250605397937098571774268863958338091486326175812168284919)
            ),
            Pairing.G1Point(
                uint256(16935319371890920010599028709808501357667428872490852912044163086211131338832),
                uint256(4431939069062621435031064976169922429860491068987996109554656960391303794357)
            ),
            Pairing.G1Point(
                uint256(3554740724820274132329602802340307763057328612131674768447857640558525478596),
                uint256(16079714048303206272442788976078113615336498444498009887901064366359938758465)
            ),
            Pairing.G1Point(
                uint256(14639299233850114854693366821679407991051094683735635940771715650978179440917),
                uint256(8335721076487741241978947197520707896913716717035779588263764276250772825527)
            ),
            Pairing.G1Point(
                uint256(17928003872082032538096154615424299166477654798428503561851164729561151765649),
                uint256(4960546183400535454884274260414600230907942976003465514489920432487055283046)
            ),
            Pairing.G1Point(
                uint256(18981045938113283612443388251792767107094240351202106144884475280364714363297),
                uint256(11864354051124467278446435225759078477043758754954030607595910513505845895374)
            ),
            Pairing.G1Point(
                uint256(5849608471641896932689050259307265823896272072351795065590531311030596429007),
                uint256(21229044712538721502348483276244406588878344472909917768994382101200976203326)
            ),
            Pairing.G1Point(
                uint256(393432175667211108483070939793661330735615114668362658763611056763370352241),
                uint256(19985271941600432926866508116673625261827724078554764982827712024353220929168)
            )
        ];
    }

    function hashToScalar(bytes memory _msg, bytes memory _dst) public pure returns (uint256) {
        bytes memory uniform_bytes = Pairing.expandMsg(_dst, _msg, 48);
        return Pairing.from_okm(uniform_bytes);
    }
}

contract BBS_Verifier {
    using Pairing for *;
    using BBS for *;

    struct PublicKey {
        Pairing.G2Point PK;
    }

    struct Signature {
        Pairing.G1Point A;
        uint256 E;
    }

    struct Proof {
        Pairing.G1Point aBar;
        Pairing.G1Point bBar;
        Pairing.G1Point d;
        uint256 eCap;
        uint256 r1Cap;
        uint256 r3Cap;
        uint256[] commitments;
        uint256 challenge;
    }

    struct InitProof {
        Pairing.G1Point[5] points;
        uint256 scalar;
    }

    function verifySignature(PublicKey memory pk, Signature memory sig, uint256[] memory msgScalar)
        public
        view
        returns (bool)
    {
        for (uint256 i = 0; i < msgScalar.length; i++) {
            require(msgScalar[i] < Pairing.SNARK_SCALAR_FIELD, "invalid scalar");
        }
        require(sig.E != 0, "invalid signature");
        require(sig.A.X != 0 || sig.A.Y != 0, "invalid signature");
        require(pk.PK.X[0] != 0 || pk.PK.X[1] != 0 || pk.PK.Y[0] != 0 || pk.PK.Y[1] != 0, "invalid public key");

        uint256 domain = calculate_domain(pk, uint64(msgScalar.length));

        Pairing.G1Point memory b = BBS.BP1();

        b = Pairing.plus(b, Pairing.scalar_mul(BBS.generators()[0], domain));

        for (uint256 i = 1; i < msgScalar.length + 1; i++) {
            b = Pairing.plus(b, Pairing.scalar_mul(BBS.generators()[i], msgScalar[i - 1]));
        }

        return Pairing.pairing(sig.A, pk.PK, Pairing.scalar_mul(sig.A, sig.E), BBS.BP2(), b, BBS.BP2Negate());
    }

    // api_id = ciphersuite_id || "H2G_HM2S_"
    // CIPHERSUITE_ID: &[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_"
    bytes constant api_id = abi.encodePacked("BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_");
    bytes constant dst = abi.encodePacked("BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_H2S_");

    function calculate_domain(PublicKey memory pk, uint64 h_points_len) public pure returns (uint256) {
        // Step 1: Create domain octets (add hPoints length as big-endian 8 bytes)
        bytes memory domOcts = uint64ToBytes(h_points_len);

        // Step 2: Add uncompressed G1 point q1
        domOcts = abi.encodePacked(domOcts, g1ToBytes(BBS.generators()[0]));

        // Step 3: Add each hPoint uncompressed
        for (uint256 i = 1; i < h_points_len + 1; i++) {
            domOcts = abi.encodePacked(domOcts, g1ToBytes(BBS.generators()[i]));
        }

        // Step 4: Add the API ID
        domOcts = abi.encodePacked(domOcts, api_id);

        // Step 5: Add compressed G2 public key
        bytes memory x1Bytes = reverseBytes(uintToBytes(pk.PK.X[1]));
        bytes memory x0Bytes = reverseBytes(uintToBytes(pk.PK.X[0]));
        bytes memory y1Bytes = reverseBytes(uintToBytes(pk.PK.Y[1]));
        bytes memory y0Bytes = reverseBytes(uintToBytes(pk.PK.Y[0]));
        bytes memory compressedPk = abi.encodePacked(x1Bytes, x0Bytes, y1Bytes, y0Bytes);

        // Step 6: Create final domain input
        bytes memory domInput = abi.encodePacked(compressedPk, domOcts);

        // Step 7: Add header length (big-endian 8 bytes) and header
        bytes1 zeroByte = 0x00;
        domInput =
            abi.encodePacked(domInput, zeroByte, zeroByte, zeroByte, zeroByte, zeroByte, zeroByte, zeroByte, zeroByte);

        // Step 8: Perform hash-to-scalar
        return BBS.hashToScalar(domInput, dst);
    }

    // Helper function to convert uint64 to bytes (big-endian)
    function uint64ToBytes(uint256 x) internal pure returns (bytes memory) {
        bytes memory b = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            b[7 - i] = bytes1(uint8(x >> (i * 8)));
        }
        return b;
    }

    function flag(uint256 y) internal pure returns (bool) {
        if (y <= Pairing.PRIME_Q - y) {
            return true;
        } else {
            return false;
        }
    }

    // Helper function to convert G1 point to bytes
    function g1ToBytes(Pairing.G1Point memory point) public pure returns (bytes memory) {
        bytes memory xBytes = reverseBytes(uintToBytes(point.X));
        bytes memory yBytes = reverseBytes(uintToBytes(point.Y));
        if (!flag(point.Y)) {
            yBytes[31] = bytes1(uint8(yBytes[31]) | uint8(1 << 7));
        }
        return abi.encodePacked(xBytes, yBytes);
    }

    function uintToBytes(uint256 x) public pure returns (bytes memory) {
        bytes memory b = new bytes(32); // A uint256 is always 32 bytes
        assembly {
            mstore(add(b, 32), x) // Store x into the bytes array
        }
        return b;
    }

    function reverseBytes(bytes memory input) internal pure returns (bytes memory) {
        bytes memory output = new bytes(32);

        for (uint256 i = 0; i < input.length; i++) {
            output[i] = input[input.length - 1 - i];
        }

        return output;
    }

    function hashToG1(bytes memory _msg, bytes memory _dst) public view returns (Pairing.G1Point memory) {
        uint256[2] memory res = Pairing.hashToPoint(_msg, _dst);

        return Pairing.G1Point(res[0], res[1]);
    }

    // function proofVerify(PublicKey memory pk, Proof memory proof, uint256[] memory disclosedMsg, uint8[] memory disclosedIndices) public view returns (bool) {

    //     uint msgLen = disclosedMsg.length;
    //     uint commitmentLen = proof.commitments.length;
    //     uint len = msgLen + commitmentLen;

    // }

    function proofVerifyInit(
        PublicKey memory pk,
        Proof memory proof,
        uint256[] memory disclosedMsg,
        uint8[] memory disclosedIndices
    ) public view returns (InitProof memory) {
        uint256 u = proof.commitments.length;
        uint256 r = disclosedIndices.length;
        uint256 l = u + r;

        uint8[] memory undisclosedIndices = complement(uint8(u), uint8(r), disclosedIndices);
        uint256 domain = calculate_domain(pk, uint64(l));
        Pairing.G1Point memory t1 = Pairing.scalar_mul(proof.bBar, proof.challenge);
        Pairing.G1Point memory t11 = Pairing.scalar_mul(proof.aBar, proof.eCap);
        Pairing.G1Point memory t12 = Pairing.scalar_mul(proof.d, proof.r1Cap);
        t1 = Pairing.plus(t1, t11);
        t1 = Pairing.plus(t1, t12);

        Pairing.G1Point memory bv1 = Pairing.scalar_mul(BBS.generators()[0], domain);
        Pairing.G1Point memory bv = Pairing.plus(BBS.BP1(), bv1);

        for (uint256 i = 0; i < disclosedIndices.length; i++) {
            uint8 disclosedIndex = disclosedIndices[i] + 1;
            uint256 disclosedm = disclosedMsg[i];
            Pairing.G1Point memory t = Pairing.scalar_mul(BBS.generators()[disclosedIndex], disclosedm);
            bv = Pairing.plus(bv, t);
        }
        uint256 challenge = proof.challenge;
        Pairing.G1Point memory d = proof.d;
        uint256 r3Cap = proof.r3Cap;
        Pairing.G1Point memory t21 = Pairing.scalar_mul(bv, challenge);
        Pairing.G1Point memory t22 = Pairing.scalar_mul(d, r3Cap);
        Pairing.G1Point memory t2 = Pairing.plus(t21, t22);

        for (uint256 i = 0; i < u; i++) {
            t2 = Pairing.plus(t2, Pairing.scalar_mul(BBS.generators()[undisclosedIndices[i] + 1], proof.commitments[i]));
        }

        return InitProof([proof.aBar, proof.bBar, proof.d, t1, t2], domain);
    }

    function complement(uint8 u, uint8 r, uint8[] memory set) public pure returns (uint8[] memory) {
        // Step 1: Create a boolean array to mark the presence of elements in the set
        bool[] memory isPresent = new bool[](u + r);

        // Step 2: Mark the elements present in the provided set
        for (uint256 i = 0; i < set.length; i++) {
            isPresent[set[i]] = true;
        }

        uint8[] memory complementSet = new uint8[](u);
        uint256 index = 0;
        for (uint8 i = 0; i < u + r; i++) {
            if (!isPresent[i]) {
                complementSet[index] = i;
                index++;
            }
        }

        return complementSet;
    }
}
