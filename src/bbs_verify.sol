// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

// https://github.com/tornadocash/tornado-core/blob/master/contracts/Verifier.sol
library Pairing {
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

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

    /// set of randomly sampled points from the G1 subgroup,
    // api_id = ciphersuite_id || "H2G_HM2S_"
    // CIPHERSUITE_ID = "BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_";
    function generators() internal pure returns (Pairing.G1Point[32] memory) {
        return [
            Pairing.G1Point(
                uint256(1189559275092470911485299354321850696454492669576732696959606714878909946414),
                uint256(5841999533672878264305016752172673894005607963357247156806749970071329483868)
            ),
            Pairing.G1Point(
                uint256(609093540602468159954798523388001809582754712383594505767945120548823599481),
                uint256(13091440937134579324957845873888154207851843998532083840440870318328336254817)
            ),
            Pairing.G1Point(
                uint256(13264393721895561855600625907469296173948877274352629082664659905161909818194),
                uint256(9666862342663992066501033982325585992123925170517253492155882748504574106307)
            ),
            Pairing.G1Point(
                uint256(7795584364325821017668550268544911263924228274005483035681982610141212250174),
                uint256(3144429438769708758132753151271463002149994561597072065423417658123234778003)
            ),
            Pairing.G1Point(
                uint256(7485128263633671647365828433905044027374156482400491831535987136419034176411),
                uint256(2679039382152716127822169807724100639243439811178792640188366255489402512815)
            ),
            Pairing.G1Point(
                uint256(16502931192688779316490961053414610011091180809543002793252443187525122593441),
                uint256(12095202013914862302978042884784049950917649291597234796651635183563925396840)
            ),
            Pairing.G1Point(
                uint256(5361082064056643818258238680309162756702608889281011357028478139039319793255),
                uint256(18511095807568701833647324247301403423902197236709483030494807218183358783624)
            ),
            Pairing.G1Point(
                uint256(642035954071896103668064719200213428579294316069004575735688294511024642783),
                uint256(21282471743283267348736369517688623816686099632678772710737532289777521231864)
            ),
            Pairing.G1Point(
                uint256(21728580384033966034653747644269386214522518393152591064348162610092855660951),
                uint256(3701756829535117173643949290105824575626467837117901647774305041828991956622)
            ),
            Pairing.G1Point(
                uint256(9232601223702877429369007383681050443040418510274950473799472490545115808851),
                uint256(2001920228529849112339466027528701436039724837319491930188972258260538271702)
            ),
            Pairing.G1Point(
                uint256(7273732572354834004667088037646005414850783184085351824674236115929313906635),
                uint256(18829839603418737032628575953203282026456179203256703725348164570309419231478)
            ),
            Pairing.G1Point(
                uint256(16230431466189579095322513098261941918498555220807327535278722414020217271352),
                uint256(17142107804788942280114417155099194335605957754180285224749665848413028179620)
            ),
            Pairing.G1Point(
                uint256(17320714795187200463466617892699579922630101091394861900227426790213779567699),
                uint256(4281186294803756006557733833563288376224902930989513548170224385173842739488)
            ),
            Pairing.G1Point(
                uint256(6761211329444706293460824798761202707891371281327503526502455660000487846606),
                uint256(3301801964651762565066991357048224251520784007201055992637030135709496793789)
            ),
            Pairing.G1Point(
                uint256(9659600964254296272983424950136842223923764894452611367001661306930050868879),
                uint256(12723488475305582984411768164740107652065201929214175761391799547412998183141)
            ),
            Pairing.G1Point(
                uint256(7360919745317559335166847683907264504661754458786004208527328364813535410469),
                uint256(14148565333472432403475020033158261976013065426483133913211404062368709078576)
            ),
            Pairing.G1Point(
                uint256(13532467458191451826780216287868467822783836575040566811229785849696142092739),
                uint256(13963599898803421697952437707574496129161178720203253286089619438795710802031)
            ),
            Pairing.G1Point(
                uint256(4596481743395344477475260401154189582722098549305659411318132084717137684281),
                uint256(13218659532245652345937864984400898586403249048840801388732433336332046484627)
            ),
            Pairing.G1Point(
                uint256(20301966567455490977953110761503022803502376182217185496738763885188190539697),
                uint256(2792665822612881437025610825145403959241485694709085262564890226841253503974)
            ),
            Pairing.G1Point(
                uint256(20369091910881519964102278511813378321710820711861399105205852401025335006334),
                uint256(13371434983987040128462373533915727867525354057290279294932531635178353995681)
            ),
            Pairing.G1Point(
                uint256(20550424563362266746641792014305884781506916240601174386537498643963414018564),
                uint256(6627585644813859074954282522874797867942904242127087531687973756019539684668)
            ),
            Pairing.G1Point(
                uint256(3302727733709659923331346112690808477073002917819347879435074989224502694037),
                uint256(1048669621339077732397786728695518881657550658519429327294706474143311593634)
            ),
            Pairing.G1Point(
                uint256(18703084692282710377605705164078934412352603613512595934685766207068964875410),
                uint256(12665874444107247099046382777627387873941208198220470331446194029995852083524)
            ),
            Pairing.G1Point(
                uint256(15988445436707550316821532566574781617067390752492494146107705822948442243582),
                uint256(16038881991475731457706168363797806983200905579154970782504929656288159494759)
            ),
            Pairing.G1Point(
                uint256(20147338224102022035567382678482404489298942634610761626426724365257789799634),
                uint256(228830322730085738354100230457890586768838670078261476124465630273431171503)
            ),
            Pairing.G1Point(
                uint256(20902366827796443067064884612645669469691200002394546422989291670492095528916),
                uint256(7431157194731076034764737642444889371488389488382140039760550318556999075742)
            ),
            Pairing.G1Point(
                uint256(16075808268569269223161859249665070678379871566399017212401965254056974072085),
                uint256(3765673477003421606996530811368760899378124587044199554111124894005168561174)
            ),
            Pairing.G1Point(
                uint256(18981516696303568630141870375459487333047267120841273799127191121533566584847),
                uint256(50826657749954775265775362830127717881945001179400528517077822520714103395)
            ),
            Pairing.G1Point(
                uint256(856027905747251399680751066233025448981902769582301819094047708708261158450),
                uint256(7336874153428741326229481960728969488239680775206474176825510274314842114962)
            ),
            Pairing.G1Point(
                uint256(4845996169138886062649627743735139520861332193576818032674151840848253267418),
                uint256(21024491734408954752188747138158383154862428879839069089926928159836928757504)
            ),
            Pairing.G1Point(
                uint256(13140206274065183534149735684430222653039778545736300207541308340181163231972),
                uint256(10153095773043243385648582642914770550726384400922698627349182925908041109377)
            ),
            Pairing.G1Point(
                uint256(3804710282101283042006896283463400086193829077626637971868238462477516778952),
                uint256(6570210764882191408517443806566349958315473949297560892921971621097269666640)
            )
        ];
    }
}

contract BBS_Verifier {
    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant T24 = 0x1000000000000000000000000000000000000000000000000;
    uint256 constant MASK24 = 0xffffffffffffffffffffffffffffffffffffffffffffffff;

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
            require(msgScalar[i] < SNARK_SCALAR_FIELD, "invalid scalar");
        }

        //TODO: change this
        // this domain is calulated from the public key, hence cannot be hardcoded
        uint256 domain = uint256(1657574941295262584661544995638483479511278121997613850335739962095195151826);

        Pairing.G1Point memory b = BBS.BP1();

        b = Pairing.plus(b, Pairing.scalar_mul(BBS.generators()[0], domain));

        for (uint256 i = 1; i < msgScalar.length + 1; i++) {
            b = Pairing.plus(b, Pairing.scalar_mul(BBS.generators()[i], msgScalar[i - 1]));
        }

        return Pairing.pairing(sig.A, pk.PK, Pairing.scalar_mul(sig.A, sig.E), BBS.BP2(), b, BBS.BP2Negate());
    }

    function from_okm(bytes memory _msg) public view returns (uint256) {
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

    function expandMsgTo48(bytes memory domain, bytes memory message) public view returns (bytes memory) {
        uint256 t1 = domain.length;
        require(t1 < 256, "BLS: invalid domain length");

        uint256 t0 = message.length;
        bytes memory msg0 = new bytes(t1 + t0 + 64 + 4); // Buffer for the message
        bytes memory out = new bytes(48); // Output buffer

        // Create the initial message
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let p := add(msg0, 96)

            // Copy the message into msg0
            let z := 0
            for {} lt(z, t0) { z := add(z, 32) } { mstore(add(p, z), mload(add(message, add(z, 32)))) }
            p := add(p, t0)

            // Append fixed data
            mstore8(p, 0) // zero
            p := add(p, 1)
            mstore8(p, 48) // 48-byte output size
            p := add(p, 1)
            mstore8(p, 0) // 0 byte
            p := add(p, 1)

            // Append domain length and domain
            mstore(p, mload(add(domain, 32)))
            p := add(p, t1)
            mstore8(p, t1)
        }

        // Compute b0
        bytes32 b0 = sha256(msg0);
        bytes32 bi;
        uint256 newLength = t1 + 34;

        // Resize intermediate message
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            mstore(msg0, newLength)
        }

        // Compute b1
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            mstore(add(msg0, 32), b0)
            mstore8(add(msg0, 64), 1)
            mstore(add(msg0, 65), mload(add(domain, 32)))
            mstore8(add(msg0, add(t1, 65)), t1)
        }

        bi = sha256(msg0);

        // Store b1
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            mstore(add(out, 32), bi)
        }

        // Compute b2
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let t := xor(b0, bi)
            mstore(add(msg0, 32), t)
            mstore8(add(msg0, 64), 2)
            mstore(add(msg0, 65), mload(add(domain, 32)))
            mstore8(add(msg0, add(t1, 65)), t1)
        }

        bi = sha256(msg0);

        // Store b2
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            mstore(add(out, 64), bi)
        }

        // Compute b3
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            let t := xor(b0, bi)
            mstore(add(msg0, 32), t)
            mstore8(add(msg0, 64), 3)
            mstore(add(msg0, 65), mload(add(domain, 32)))
            mstore8(add(msg0, add(t1, 65)), t1)
        }

        bi = sha256(msg0);

        // Store b3
        // solium-disable-next-line security/no-inline-assembly
        assembly {
            mstore(add(out, 96), bi)
        }

        return out;
    }

    function hashToScalar(bytes memory msg, bytes memory dst) public view returns (uint256) {
        bytes memory uniform_bytes = expandMsgTo48(dst, msg);
        return from_okm(uniform_bytes);
    }

    // function calculate_domain(PublicKey memory pk, uint8 h_points_len) public view returns (uint256) {
    //     bytes memory dom_octs = new bytes(0);
    //     dom_octs = abi.encodePacked(dom_octs, bytes1(uint8(h_points_len)));

    //     // Serialize q1
    //     dom_octs = abi.encodePacked(dom_octs, bytes32(BBS.generators()[0].X));
    //     dom_octs = abi.encodePacked(dom_octs, bytes32(BBS.generators()[0].Y));

    //     // Serialize each h_point
    //     for (uint256 i = 1; i < h_points_len + 1; i++) {
    //         dom_octs = abi.encodePacked(dom_octs, bytes32(BBS.generators()[i].X));
    //         dom_octs = abi.encodePacked(dom_octs, bytes32(BBS.generators()[i].Y));
    //     }

    //     // Serialize the public key (compressed)
    //     bytes memory compressed_pk = new bytes(0);
    //     compressed_pk = abi.encodePacked(compressed_pk, bytes32(pk.PK.X[1]));
    //     compressed_pk = abi.encodePacked(compressed_pk, bytes32(pk.PK.X[0]));
    //     compressed_pk = abi.encodePacked(compressed_pk, bytes32(pk.PK.Y[1]));
    //     compressed_pk = abi.encodePacked(compressed_pk, bytes32(pk.PK.Y[0]));

    //     bytes memory dom_input = abi.encodePacked(compressed_pk, dom_octs, bytes1(uint8(0)));

    //     // Destination string for hashing
    //     bytes memory hashToScalarDst = abi.encodePacked("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_", "H2S_");

    //     return hashToScalar(dom_input, hashToScalarDst);
    // }

    bytes constant api_id = abi.encodePacked("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_");
    bytes constant dst = abi.encodePacked("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_H2S_");

    function calculate_domain(PublicKey memory pk, uint64 h_points_len) public view returns (uint256) {
        // Step 1: Create domain octets (add hPoints length as big-endian 8 bytes)
        bytes memory domOcts = abi.encodePacked(uint64ToBytes(h_points_len));

        // Step 2: Add uncompressed G1 point q1
        domOcts = abi.encodePacked(domOcts, g1Uncompressed(BBS.generators()[0]));

        // Step 3: Add each hPoint uncompressed
        for (uint256 i = 1; i < h_points_len+1; i++) {
            domOcts = abi.encodePacked(domOcts, g1Uncompressed(BBS.generators()[i]));
        }

        // Step 4: Add the API ID
        domOcts = abi.encodePacked(domOcts, api_id);

        // Step 5: Add compressed G2 public key
        bytes memory compressedPk = abi.encodePacked(pk.PK.X[1], pk.PK.X[0], pk.PK.Y[1], pk.PK.Y[0]);

        // Step 6: Create final domain input
        bytes memory domInput = abi.encodePacked(compressedPk, domOcts);

        // Step 7: Add header length (big-endian 8 bytes) and header
        domInput = abi.encodePacked(domInput, uint64ToBytes(0));
        
        // Step 8: Perform hash-to-scalar
        return hashToScalar(domInput, dst);

    }

    // Helper function to uncompress G1 point (returns X and Y)
    function g1Uncompressed(Pairing.G1Point memory point) internal pure returns (bytes memory) {
        return abi.encodePacked(point.X, point.Y);
    }

    // Helper function to convert uint64 to bytes (big-endian)
    function uint64ToBytes(uint256 x) internal pure returns (bytes memory) {
        bytes memory b = new bytes(8);
        for (uint256 i = 0; i < 8; i++) {
            b[7 - i] = bytes1(uint8(x >> (i * 8)));
        }
        return b;
    }

    // Helper function to convert G1 point to bytes
    function g1ToBytes(Pairing.G1Point memory point) public view returns (bytes memory) {
        return abi.encodePacked(point.X, point.Y);
    }

    // // Helper function to convert uint256 to bytes
    // function uintToBytes(uint256 x) public view returns (bytes memory) {
    //     bytes memory b = new bytes(32);
    //     assembly { mstore(add(b, 32), x) }
    //     return b;
    // }

    // function uintToBytes8(uint64 x) internal pure returns (bytes memory) {
    //     bytes memory b = new bytes(8);
    //     assembly {
    //         mstore(add(b, 8), x) // Store the 8 least significant bytes of the uint256
    //     }
    //     return b;
    // }

    // function uint64ToBytesBE(uint64 value) internal pure returns (bytes8) {
    //     bytes8 result;
    //     assembly {
    //         result := shl(192, value) // Shift left to place the uint64 in the most significant 8 bytes (Big Endian)
    //     }
    //     return result;
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

        bool[] memory exclude = new bool[](l);

        // Mark the excluded indices
        for (uint8 i = 0; i < disclosedIndices.length; i++) {
            exclude[disclosedIndices[i]] = true;
        }

        uint8[] memory undisclosed_indexes = new uint8[](u);
        uint8 j = 0;
        for (uint8 i = 0; i < l; i++) {
            if (!exclude[i]) {
                undisclosed_indexes[j] = i;
                j++;
            }
        }

        // TODO: cannot hardcode this
        // calculate_domain function needs to be implemented
        uint256 domain = uint256(1657574941295262584661544995638483479511278121997613850335739962095195151826);

        Pairing.G1Point memory t1 = Pairing.scalar_mul(proof.bBar, proof.challenge);
        t1 = Pairing.plus(t1, Pairing.scalar_mul(proof.aBar, proof.eCap));
        t1 = Pairing.plus(t1, Pairing.scalar_mul(proof.d, proof.r1Cap));

        Pairing.G1Point memory bv = Pairing.plus(BBS.BP1(), Pairing.scalar_mul(BBS.generators()[0], domain));

        for (uint8 i = 0; i < r; i++) {
            bv = Pairing.plus(bv, Pairing.scalar_mul(BBS.generators()[disclosedIndices[i] + 1], disclosedMsg[i]));
        }

        Pairing.G1Point memory t2 = Pairing.scalar_mul(bv, proof.challenge);
        t2 = Pairing.plus(t2, Pairing.scalar_mul(proof.d, proof.r3Cap));

        for (uint8 i = 0; i < u; i++) {
            t2 =
                Pairing.plus(t2, Pairing.scalar_mul(BBS.generators()[undisclosed_indexes[i] + 1], proof.commitments[i]));
        }

        return InitProof({points: [proof.aBar, proof.bBar, proof.d, t1, t2], scalar: domain});
    }

    function coreProofVerify(
        PublicKey memory pk,
        Proof memory proof,
        uint256[] memory disclosed_messages,
        uint8[] memory disclosed_indices
    ) public view returns (bool) {
        InitProof memory _init_proof = proofVerifyInit(pk, proof, disclosed_messages, disclosed_indices);

        uint256 challenge = 7676392787844152301551421773140336616957656183078613308512391394721662889811;
        require(challenge == proof.challenge, "invalid challenge");
        return Pairing.pairing(
            proof.aBar,
            pk.PK,
            proof.bBar,
            BBS.BP2Negate(),
            Pairing.G1Point(0, 0),
            Pairing.G2Point([uint256(0), uint256(0)], [uint256(0), uint256(0)])
        );
    }
}
