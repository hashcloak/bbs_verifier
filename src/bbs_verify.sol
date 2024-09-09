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
                uint256(20777160656769770296920907689779400362548610292690633793553965468222558198628),
                uint256(15646964583660897684471766551845809741020611821959915197826685959370263487106)
            ),
            Pairing.G1Point(
                uint256(8536227939158618265175886202535764436304116068200625472123099584539578337421),
                uint256(5954339734284052721289034903148025734427628037818105080548676273909315194809)
            ),
            Pairing.G1Point(
                uint256(6966706174358697579930351667004530084801148414965274884121192450141672945045),
                uint256(498137001355230954510980595837383274359060711775308369155468447488137646784)
            ),
            Pairing.G1Point(
                uint256(5438105816700008286121294878063209652767146817832975561511179458352725658814),
                uint256(13021486400522453264827797557714368123643448446761912363585463162459449483576)
            ),
            Pairing.G1Point(
                uint256(15171615269862876518863358428943843041940125537931654107248803187352985612430),
                uint256(8586269445696959752467230517015982159589605142846712629705147542333554398226)
            ),
            Pairing.G1Point(
                uint256(5051258433525325219521083013996569208555314039239043276349703928699399069822),
                uint256(1681200095591041471217584326897093992437898040845292616132300787352510165206)
            ),
            Pairing.G1Point(
                uint256(21753791110380467783584742654428448358401879578443602255216671622947444229131),
                uint256(12897421398847559438022107398410073458721218334567793302364517965458109325783)
            ),
            Pairing.G1Point(
                uint256(16764643433735538422696377983000462108379103633839334040884164967942899425632),
                uint256(21668442295160040501298591489870463866263588933839580031841498538860744377064)
            ),
            Pairing.G1Point(
                uint256(4013792417864936116677013992620797522948679222441355805643575852230193971807),
                uint256(19852825205047261307491565420844666947509925513041998257351294192421458440775)
            ),
            Pairing.G1Point(
                uint256(15235789988489366351078142629661614055604735578863140907495220462928998553454),
                uint256(20439547806095900407701608374086160199235593142344143339294376261253535125704)
            ),
            Pairing.G1Point(
                uint256(9996721774782352741822533151204121063290685493223672922385484813016764547435),
                uint256(5385215156704978100874262819044322518580987328116718995648264785451005585049)
            ),
            Pairing.G1Point(
                uint256(5281253127589211866317136159546081932420549096521808911709313169185921240315),
                uint256(20288355738516256198974876062156075712583149333330237624015549545532548348625)
            ),
            Pairing.G1Point(
                uint256(19726372169683222465353857614018548655417268491715027507748163032820279050001),
                uint256(15730520802198311908481180389403348070871209305730811316454055853065609274596)
            ),
            Pairing.G1Point(
                uint256(16282107833837338794414548666268543192621108022168534422526344422541233598547),
                uint256(18839797638941304593430186468859495729298581516557153877529516048112227423101)
            ),
            Pairing.G1Point(
                uint256(18874646234839083109587086472635929908281290527959495976476575081871486139158),
                uint256(5899268376799611138981545417756396923956604357355852186412920150880814773404)
            ),
            Pairing.G1Point(
                uint256(14067505039747626814907528316498505303099495619235188348953524790328559486810),
                uint256(7389458255504902601690249514233706134057312606508220806800150482908277143952)
            ),
            Pairing.G1Point(
                uint256(15251189857028682076348637554874405070837309154537315899281290887655859816680),
                uint256(16018647581228689556732893544203926589846441512412840141045889388189453831778)
            ),
            Pairing.G1Point(
                uint256(8407462810135920786229033311650037150039055119197272220015509905962367850170),
                uint256(14732513882313499052827330088156636092855864050141475781755997887436735956009)
            ),
            Pairing.G1Point(
                uint256(13750370747778111173930259600316743671647606292973600136889468816552093463131),
                uint256(4925544525751198104051867872908540244212485100666666131834709922969647364368)
            ),
            Pairing.G1Point(
                uint256(953531922420076853769190318068935673991359154293184324057382801940087541058),
                uint256(6731416650799582766230739196791467550856695320647303187522338429522254332700)
            ),
            Pairing.G1Point(
                uint256(3173110439651164793311982626309113950349756763187602101531800216231599804928),
                uint256(5263771206696772457201153819901747129808438505593373196131282748808133634910)
            ),
            Pairing.G1Point(
                uint256(16027186659618718627499438833089566017580893109579552868678260272853087747448),
                uint256(21669689197811587869325211547657060943650336091419965475925811576944725616226)
            ),
            Pairing.G1Point(
                uint256(2620496790408129640731288723907750415832229288442662087498780982382004803756),
                uint256(16634155193153187661065141800307333031872218873118737169677190730431489499026)
            ),
            Pairing.G1Point(
                uint256(6309780264175077010538511403382530678267024106768286948652182798683470651010),
                uint256(10982639597997082531491430076512905403812001970252757816241040537962831959305)
            ),
            Pairing.G1Point(
                uint256(9592682014657652197114295404077004605429496936223920902324738714033691481088),
                uint256(14198367460357479057844799780559288048118616493274983350996740674423475576784)
            ),
            Pairing.G1Point(
                uint256(19133366293226796741137871486083885980769381521956342048688966627808507290439),
                uint256(1384224247742243466141266003325617983111978855774830111959515579286697418288)
            ),
            Pairing.G1Point(
                uint256(695990285095860103161233536714697342071230124499514229245010811142354057664),
                uint256(4880859521053654346795550932209273066894742740446493897902102531384430522307)
            ),
            Pairing.G1Point(
                uint256(18931247865367364266304964492516702793433990171087918161903347545062075665767),
                uint256(9945539770767347447775431528601480352781102902761543485719881461446315717486)
            ),
            Pairing.G1Point(
                uint256(1072683858589137215167630848551953164378072346728719245546816404388463668797),
                uint256(9332169772935827172513162711432044685970908789763810575299827679325424183666)
            ),
            Pairing.G1Point(
                uint256(21275808812052109345856593525178828352516671937584975416601023894900566571048),
                uint256(13165158610144979969982441431462117096010453879273262805716736386147711325322)
            ),
            Pairing.G1Point(
                uint256(1456643669371327517414661572825117577606274230242222820722949822081701218843),
                uint256(3771723902160285912564981419437554136700904455540292345569375427658737375328)
            ),
            Pairing.G1Point(
                uint256(18147240790321515030764012387388409927697035957099496685209442560219459579776),
                uint256(960007873849796184736529840000880494495810739716445769161195881582431744269)
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
        uint256 domain = uint256(14063053651636558252041470698983588143630819978768317207563375018948447002197);

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
    //     compressed_pk = abi.encodePacked(compressed_pk, bytes32(pk.PK.X[0]));
    //     compressed_pk = abi.encodePacked(compressed_pk, bytes32(pk.PK.X[1]));
    //     compressed_pk = abi.encodePacked(compressed_pk, bytes32(pk.PK.Y[0]));
    //     compressed_pk = abi.encodePacked(compressed_pk, bytes32(pk.PK.Y[1]));

    //     bytes memory dom_input = abi.encodePacked(compressed_pk, dom_octs, bytes1(uint8(0)));

    //     // Destination string for hashing
    //     bytes memory hashToScalarDst = abi.encodePacked("BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_", "H2S_");

    //     return hashToScalar(dom_input, hashToScalarDst);
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
        uint256 domain = uint256(14063053651636558252041470698983588143630819978768317207563375018948447002197);

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

        uint256 challenge = 13955571932877160789381516654212174441652092085432874070047454718791062279942;
        // 6831971804760012414492655217185150406827018329771346964145455923701508846655
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
