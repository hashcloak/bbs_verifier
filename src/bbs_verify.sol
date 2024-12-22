// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

// https://github.com/tornadocash/tornado-core/blob/master/contracts/Verifier.sol
library Pairing {
    uint256 constant PRIME_Q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    uint256 constant SNARK_SCALAR_FIELD = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant T24 = 0x1000000000000000000000000000000000000000000000000;
    uint256 constant MASK24 = 0xffffffffffffffffffffffffffffffffffffffffffffffff;

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
        require(len_in_bytes == 48 || len_in_bytes == 96, "BLS: invalid length");
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
}

library BBS {
    using Pairing for *;

    /// P1 a random point other than BP1 generated accoring to draft
    function P1() internal pure returns (Pairing.G1Point memory) {
        return Pairing.G1Point(
            uint256(7738860219269362160002109478394842060990190871738832255540382874922375322334),
            uint256(8255268479661695615178834896135584953541182794935974658059743263102507888551)
        );
    }
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
                uint256(1173147175266788629161386345780835162643573498245275798226483331942833064090),
                uint256(3145771569857800812612490171819094524500692685865840936106036825748970017425)
            ),
            Pairing.G1Point(
                uint256(17959488178071103586887041079899546140481668450262589167571954617203990003931),
                uint256(9373372757406534579589807812909162170493381282282055995414262223554020738469)
            ),
            Pairing.G1Point(
                uint256(16380393904719381847123808879092138100099862519814676706991964183592469278036),
                uint256(13419064243729972931910835325273073158849664397029543553671213683259211229016)
            ),
            Pairing.G1Point(
                uint256(10011265545506972230685287172414929655892727331155130996433485506147641614716),
                uint256(14334430316185001240382705869019108438296174635774957711616746050867178914052)
            ),
            Pairing.G1Point(
                uint256(12283399099910692471540027513043652828679217720294980096786616079477268990181),
                uint256(11769172645066528297868527814827529439332284730728660166652006752452954078501)
            ),
            Pairing.G1Point(
                uint256(17930349550811222065814166468413282560106430323892614573707741975714346648713),
                uint256(11377920438361863175939308656552273126249742602955706876624924893171319025886)
            ),
            Pairing.G1Point(
                uint256(15307523606231210529567583070832003860853992124039141147755409127163272476371),
                uint256(21488624556484663372323909443350226738477135288629327670976400472289430374826)
            ),
            Pairing.G1Point(
                uint256(5654726928524216305838010965008022899653349750468499008338514899070443399341),
                uint256(3756198776334014955912930933213029525470616112230126974228432834467018709135)
            ),
            Pairing.G1Point(
                uint256(9957347644045616734873860422778161256248062700908303783670828208992688052735),
                uint256(2504637797351340999662067003596356069394974879247629311686868148743357461560)
            ),
            Pairing.G1Point(
                uint256(16403330996054574763530751561633094592150996050583743138829995864377497247319),
                uint256(6446773961720043854294133141565879255764271196611564877856564159069018565043)
            ),
            Pairing.G1Point(
                uint256(15888451533231955509199210830760113858577831611602424876567905922136007402938),
                uint256(19215166253598153274963866121746167474460293952141063412468175431374129976271)
            ),
            Pairing.G1Point(
                uint256(15022652498007559408533533252004001090243793868973868481519026229097007632403),
                uint256(7581984809942871632514194443085566848480942630840856603320301783436961387452)
            ),
            Pairing.G1Point(
                uint256(1302769090331320941504744703455039649525967990478864888817914162687010352982),
                uint256(1755344547472618877820060641259140462945806891865693089639197701837443816710)
            ),
            Pairing.G1Point(
                uint256(16153163936571489731405338144926242235073298112968333929725002837850835181442),
                uint256(19156488576420737399265847256730436450788645157454417898001804440108336200602)
            ),
            Pairing.G1Point(
                uint256(5616223417513003685510602580688354394669532788546049890336500094750490381205),
                uint256(13034311885166364200155507714477771802690604579507733871196271987058238904912)
            ),
            Pairing.G1Point(
                uint256(9643655102806455741028903115519435474821000055663403189061819001309524016312),
                uint256(6069835868166716414650319279327329841781783256719779078423850942341511861503)
            ),
            Pairing.G1Point(
                uint256(17431199659754885273798744084025037632951955016606485628640772292056074297332),
                uint256(19132617647673639002459190544261948975215985865914002493727977475439438432512)
            ),
            Pairing.G1Point(
                uint256(12373734458317617314628028459837027294291776348305043081080349834239561189694),
                uint256(3677566406048315197483187111520828710854955894386595774524835535775650560611)
            ),
            Pairing.G1Point(
                uint256(20499341640479498631238075777144206238051422119662911607654502549297729453659),
                uint256(19935999804740659661606097165507119603913056856868137635864162257318848300092)
            ),
            Pairing.G1Point(
                uint256(7934132476930643356156605467530739933255469367028804294978638893922378804050),
                uint256(21820122857806683337418498246714352760212668089496828245789008781586555155247)
            ),
            Pairing.G1Point(
                uint256(2562823402937553216280089632709848292947373555861404964615463993775182481712),
                uint256(18328941045591590880349240999088240844303194584276276064795602490921550857312)
            ),
            Pairing.G1Point(
                uint256(153759350313213566109302013407252970674980566321179731901501462604730312556),
                uint256(3210752135885401873718647495268941916555047559524287797801711501762371481634)
            ),
            Pairing.G1Point(
                uint256(13636514067428181095787693192440452218537567466091766340342788597701268153332),
                uint256(4358088473862711746982381633802222194830186459269349673950859337538364305948)
            ),
            Pairing.G1Point(
                uint256(17634058837307309296396615465374994084623484518869477504834248502759534693214),
                uint256(16024827000017053814187936039847237209990298815264560739004817629059591452009)
            ),
            Pairing.G1Point(
                uint256(16453569312504957028723515610426556180810266427872941041927105148986965294797),
                uint256(2732734973218124539348608155070219728296389137934310881487333611087202931682)
            ),
            Pairing.G1Point(
                uint256(4114269611738334173210087396419950646428491603710706268161251549816070561722),
                uint256(17386111633153003536660733463215327520706937094733684811286033605149170024869)
            ),
            Pairing.G1Point(
                uint256(13731159138308940009567543434701339242413399457300072091360119309795210930894),
                uint256(12337453279912739068938084638286241109537513029389490150088392770161163819649)
            ),
            Pairing.G1Point(
                uint256(8204288829875205585296664861597277902356097075957994159764849007659776230237),
                uint256(16575669935574012423291879085108280061678829639629721526694452695998565252931)
            ),
            Pairing.G1Point(
                uint256(2076322709672338731204413192547335576967683590546912106453962207464210345840),
                uint256(13089051593672529609077868426152948484604245086678840892477851929424127619444)
            ),
            Pairing.G1Point(
                uint256(17019919734230251763787743889078305305757454687543403321012198101635472162460),
                uint256(5185191194715695775180744754547732566196814012314493969009466713176559661918)
            ),
            Pairing.G1Point(
                uint256(13241862004939365319152232354537337712254726153508919319935262820095413713569),
                uint256(8830790179260831569867944674002905218695496479029728900041819747197656672434)
            ),
            Pairing.G1Point(
                uint256(12396288641390375580945105728413265282035324302647555995968168512592330840740),
                uint256(7006476850124921792464455340149262004736826328762868987536397881081947430797)
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
        // TODO: add missing checks
        // valid public key
        // valid signature
        for (uint256 i = 0; i < msgScalar.length; i++) {
            require(msgScalar[i] < Pairing.SNARK_SCALAR_FIELD, "invalid scalar");
        }
        require(sig.E != 0, "invalid signature");
        require(sig.A.X != 0 || sig.A.Y != 0, "invalid signature");
        require(pk.PK.X[0] != 0 || pk.PK.X[1] != 0 || pk.PK.Y[0] != 0 || pk.PK.Y[1] != 0, "invalid public key");

        uint256 domain = calculate_domain(pk, uint64(msgScalar.length));

        Pairing.G1Point memory b = BBS.P1();

        b = Pairing.plus(b, Pairing.scalar_mul(BBS.generators()[0], domain));

        for (uint256 i = 1; i < msgScalar.length + 1; i++) {
            b = Pairing.plus(b, Pairing.scalar_mul(BBS.generators()[i], msgScalar[i - 1]));
        }

        return Pairing.pairing(sig.A, pk.PK, Pairing.scalar_mul(sig.A, sig.E), BBS.BP2(), b, BBS.BP2Negate());
    }

    // api_id = ciphersuite_id || "H2G_HM2S_"
    // CIPHERSUITE_ID: &[u8] = b"BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_"
    bytes constant api_id = "BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_";
    bytes constant dst = "BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_H2S_";

    function calculate_domain(PublicKey memory pk, uint64 h_points_len) public pure returns (uint256) {
        // Step 1: Create domain octets (add hPoints length as big-endian 8 bytes)
        bytes memory domOcts = uint64ToBytes(h_points_len);

        // Step 2: Add uncompressed G1 point q1
        domOcts = abi.encodePacked(domOcts, serializeCompressed(BBS.generators()[0]));

        // Step 3: Add each hPoint uncompressed
        for (uint256 i = 1; i < h_points_len + 1; i++) {
            domOcts = abi.encodePacked(domOcts, serializeCompressed(BBS.generators()[i]));
        }

        // Step 4: Add the API ID
        domOcts = abi.encodePacked(domOcts, api_id);

        // Step 5: Add compressed G2 public key
        bytes memory compressedPk = serializeCompressedG2(pk.PK);

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
        bytes memory result = new bytes(8); // uint64 takes 8 bytes
        assembly {
            let resultPtr := add(result, 32)
            mstore(resultPtr, shl(192, x))
        }
        return result;
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
        bytes memory xBytes = uintToBytes(point.X);
        // bytes memory yBytes = reverseBytes(uintToBytes(point.Y));
        // if (!flag(point.Y)) {
        //     yBytes[31] = bytes1(uint8(yBytes[31]) | uint8(1 << 7));
        // }
        return xBytes;
    }

    function serializeCompressed(Pairing.G1Point memory point) public pure returns (bytes memory) {
        // Extract the sign bit (0 for even, 1 for odd)
        uint8 signBit = 0;
        if (!flag(point.Y)) {
            signBit = 1;
        }

        // Add the sign bit to the most significant bit of x
        uint256 compressedX = point.X | (uint256(signBit) << 255);

        // Serialize the compressed x-coordinate to 32 bytes
        return reverseBytes(abi.encodePacked(compressedX));
    }

    function serializeCompressedG2(Pairing.G2Point memory point) public pure returns (bytes memory) {
        uint8 signBit = 0;
        // Extract the sign bit (0 for even, 1 for odd) of y.imaginary
        if (!flag(point.Y[0])) {
            signBit = 1;
        }

        // Add the sign bit to the most significant bit of x.real
        uint256 compressedXReal = point.X[0] | (uint256(signBit) << 255);
        // Serialize the compressed x.real and x.imaginary coordinates
        return reverseBytes(abi.encodePacked(compressedXReal, point.X[1]));
    }

    function uintToBytes(uint256 x) public pure returns (bytes memory) {
        bytes memory b = new bytes(32); // A uint256 is always 32 bytes
        assembly {
            mstore(add(b, 32), x) // Store x into the bytes array
        }
        return b;
    }

    function reverseBytes(bytes memory input) internal pure returns (bytes memory) {
        bytes memory output = new bytes(input.length);

        for (uint256 i = 0; i < (input.length + 1) / 2; i++) {
            output[i] = input[input.length - 1 - i];
            output[input.length - 1 - i] = input[i];
        }

        return output;
    }

    function verifyProof(
        PublicKey memory pk,
        Proof memory proof,
        uint256[] memory disclosedMsg,
        uint8[] memory disclosedIndices
    ) public view returns (bool) {
        InitProof memory initProof = proofVerifyInit(pk, proof, disclosedMsg, disclosedIndices);
        uint256 challenge = calculateProofChallenge(initProof, disclosedMsg, disclosedIndices);

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
        Pairing.G1Point memory temp1 =
            Pairing.plus(Pairing.scalar_mul(proof.aBar, proof.eCap), Pairing.scalar_mul(proof.d, proof.r1Cap));

        Pairing.G1Point memory t1 = Pairing.plus(Pairing.scalar_mul(proof.bBar, proof.challenge), temp1);

        Pairing.G1Point memory bv1 = Pairing.scalar_mul(BBS.generators()[0], domain);
        Pairing.G1Point memory bv = Pairing.plus(BBS.BP1(), bv1);

        for (uint256 i = 0; i < disclosedIndices.length; i++) {
            Pairing.G1Point memory t = Pairing.scalar_mul(BBS.generators()[disclosedIndices[i] + 1], disclosedMsg[i]);
            bv = Pairing.plus(bv, t);
        }
        uint256 challenge = proof.challenge;
        Pairing.G1Point memory d = proof.d;
        Pairing.G1Point memory t2 = Pairing.plus(Pairing.scalar_mul(bv, challenge), Pairing.scalar_mul(d, proof.r3Cap));

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

    function calculateProofChallenge(
        InitProof memory initProof,
        uint256[] memory disclosedMsg,
        uint8[] memory disclosedIndices
    ) public pure returns (uint256) {
        require(disclosedMsg.length == disclosedIndices.length, "invalid length");

        uint256 totalLength = 8 + disclosedMsg.length * (8 + 32) + initProof.points.length * 64 + 32 + 8;
        bytes memory serializeBytes = new bytes(totalLength);

        uint256 serializeBytesPtr;
        assembly {
            serializeBytesPtr := add(serializeBytes, 0x20)
        }

        bytes memory lengthBytes = uint64ToBytes(disclosedIndices.length);
        assembly {
            let lenPtr := add(lengthBytes, 0x20)
            mstore(serializeBytesPtr, mload(lenPtr)) // Copy the lengthBytes (8 bytes)
            serializeBytesPtr := add(serializeBytesPtr, 8)
        }

        // Serialize disclosedIndices and disclosedMsg
        for (uint256 i = 0; i < disclosedMsg.length; i++) {
            bytes memory indexBytes = uint64ToBytes(uint64(disclosedIndices[i]));
            bytes memory msgBytes = reverseBytes(uintToBytes(disclosedMsg[i]));

            assembly {
                let indexPtr := add(indexBytes, 0x20)
                mstore(serializeBytesPtr, mload(indexPtr))
                serializeBytesPtr := add(serializeBytesPtr, 8)
            }

            // Concatenate msgBytes (32 bytes)
            assembly {
                let msgPtr := add(msgBytes, 0x20)
                mstore(serializeBytesPtr, mload(msgPtr))
                serializeBytesPtr := add(serializeBytesPtr, 32)
            }
        }

        // Serialize G1 points
        for (uint256 i = 0; i < initProof.points.length; i++) {
            bytes memory pointBytes = g1ToBytes(initProof.points[i]);

            assembly {
                let pointPtr := add(pointBytes, 0x20)
                mstore(serializeBytesPtr, mload(pointPtr))
                mstore(add(serializeBytesPtr, 0x20), mload(add(pointPtr, 0x20))) // Copy 64 bytes for G1 point
                serializeBytesPtr := add(serializeBytesPtr, 64)
            }
        }

        // Serialize scalar (32 bytes)
        bytes memory scalarBytes = reverseBytes(uintToBytes(initProof.scalar));
        assembly {
            let scalarPtr := add(scalarBytes, 0x20)
            mstore(serializeBytesPtr, mload(scalarPtr)) // Copy 32 bytes
            serializeBytesPtr := add(serializeBytesPtr, 32)
        }

        assembly {
            mstore(serializeBytesPtr, 0) // Zero bytes
            serializeBytesPtr := add(serializeBytesPtr, 8)
        }

        // Return the calculated hash using BBS.hashToScalar
        return BBS.hashToScalar(serializeBytes, dst);
    }
}
