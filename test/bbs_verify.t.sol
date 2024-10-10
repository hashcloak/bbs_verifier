// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {Test, console} from "forge-std/Test.sol";
import {BBS_Verifier, Pairing, BBS} from "../src/bbs_verify.sol";

contract BBS_VerifierTest is Test {
    BBS_Verifier.Signature public sig;
    BBS_Verifier.PublicKey public pk;
    BBS_Verifier.Proof public proof;
    uint256[] public msgScalar;

    function setUp() public {
        // msg
        msgScalar = [
            uint256(2266124219189018131),
            uint256(15553430782966677989),
            uint256(12252424663184168987),
            uint256(1969625583697874321),
            uint256(8798495767124183927),
            uint256(4743228516788447402),
            uint256(8902949269966882790),
            uint256(1449287668463434640),
            uint256(16234881692928710824),
            uint256(13179618089750662187),
            uint256(2132060277757908505),
            uint256(7469040032366907693),
            uint256(286998145258191934),
            uint256(12012091655379394047),
            uint256(8227232354837253112),
            uint256(4245507022592209702),
            uint256(15341480955034186690),
            uint256(13372014594622549612),
            uint256(4775774716639663789),
            uint256(3980695616762244981),
            uint256(13661186179188099084),
            uint256(11843969393565636405),
            uint256(584132371283407898),
            uint256(7718042704038564351),
            uint256(1113807059037267782),
            uint256(12590950049868647788),
            uint256(11822948952081078471),
            uint256(14688457861979401824),
            uint256(4766154862542150769),
            uint256(5861875202524790730),
            uint256(1386588526036119096)
        ];

        // signature
        sig.A = Pairing.G1Point(
            uint256(16605941458272293469898459593559962462499885703597334825353004900710945536242),
            uint256(15276896411257112930580737499920866088375905247814230771366087132031781450435)
        );
        sig.E = uint256(20145301027381071188604537375435971326340204640470956156185142406370688319043);

        // public key
        pk.PK = Pairing.G2Point(
            [
                uint256(18995555010723360870807378930627885936580090638932106191711429555833420406651),
                uint256(12645745131803946564517015766083220615208734349162119496713913738635122768190)
            ],
            [
                uint256(3610369380377107663814668440952629069799181095497307971279336242375649233639),
                uint256(15886074934859455688300902859116025241719978288647494891665273100122551253775)
            ]
        );

        proof.aBar = Pairing.G1Point(
            uint256(17705900040482640200318765868397816899423300068827258330107828571873441470719),
            uint256(7713906401864379473036154127800301923576930562959621253303600800199073334118)
        );
        proof.bBar = Pairing.G1Point(
            uint256(21727344193746663605105815693486793700736011477614477583899999224491814279994),
            uint256(3107868243865832229708730395440182823160504417487161073020576660932813536129)
        );
        proof.d = Pairing.G1Point(
            uint256(15259877521667048732653966731531866330870155623999372073511953831671978329220),
            uint256(10346279138881905705140583326619164208036592391424952436660826945178815367429)
        );
        proof.eCap = uint256(895560299474401253372773501875631392367182095767290314841076259590095084586);
        proof.r1Cap = uint256(11193219439787925012791936928927829256760578552338662201715987339199095941227);
        proof.r3Cap = uint256(15267152252107021640270952755495037380174121953972815385187286027940019996824);
        proof.challenge = uint256(17070931957668459394149291496811547077907740596908548642717845173554837520766);

        proof.commitments = new uint256[](28);
        proof.commitments[0] = uint256(19095727655211535891907424632625597788660896504069139787113033189477200901164);
        proof.commitments[1] = uint256(19376086836081848875356199522059787747649523185103503820918546873546803656837);
        proof.commitments[2] = uint256(294630661519046963443548105138813757424736295965011860489516719425258301868);
        proof.commitments[3] = uint256(2669991038723578516998124743106790553264755193437596445025159197580315246913);
        proof.commitments[4] = uint256(9347384312453102707431895387088312145715418559983462799650963982682084827252);
        proof.commitments[5] = uint256(10423402888507524428295410032922396350307052955495214158940561611559586857682);
        proof.commitments[6] = uint256(21667666739487631443855567302732869873626852318523924021971922974064015548203);
        proof.commitments[7] = uint256(2391574914373737044908304675905879726184592881619003159020770247137231086890);
        proof.commitments[8] = uint256(6278153666110445575600940082413845807068412500507616321015839605239269964481);
        proof.commitments[9] = uint256(17407116680557453084774309595190475554418201715886488721842472385513811947490);
        proof.commitments[10] = uint256(8501318769770573792305740921919152496772914721536223890699332307683117426648);
        proof.commitments[11] = uint256(10051701914974888853862296233599397109887353152719520271166239879253384300084);
        proof.commitments[12] = uint256(4629893339370850175540759987958849789651933707400277961494579665229717132314);
        proof.commitments[13] = uint256(19733193495966317727151773873301557383437837661981698399123721056474042649121);
        proof.commitments[14] = uint256(16581440502746205531254170374821787090797536920805429488227888885103068899696);
        proof.commitments[15] = uint256(4648351001408854396093087060766510007903087217506064759222363505293687917509);
        proof.commitments[16] = uint256(5232978090956285957326199431497654863020266920439885149705611444557525841377);
        proof.commitments[17] = uint256(10378971376370607204122093933171648619962601242767826857548254941729314144779);
        proof.commitments[18] = uint256(10636096558455749185044536222842024797504005940994930068820626467354940043941);
        proof.commitments[19] = uint256(13014117807481833912707217404666717118061234026083047800320547313575178119938);
        proof.commitments[20] = uint256(9468061149785714375845841584548255079305964111362932915002031399165874890540);
        proof.commitments[21] = uint256(12080296571110568157656356440360410776064799132442611756186811013992503842789);
        proof.commitments[22] = uint256(8406199401805359744205934469936213843102959323070335564794326616494411213164);
        proof.commitments[23] = uint256(13146762841746050965674929823955906169083360848059985425714661251008235930384);
        proof.commitments[24] = uint256(18062184243758250054044805146678460481140799371280738494887026946927689738624);
        proof.commitments[25] = uint256(4689669766214571146361709842956272925578589085257066757670840626355289827344);
        proof.commitments[26] = uint256(19717012933748023731747259246552232456988022985282562051094427191782572854304);
        proof.commitments[27] = uint256(19403246504848923420955727303103540860884754495247099508968984133479080201474);
    }

    function test_verify() public {
        BBS_Verifier verifier;
        verifier = new BBS_Verifier();

        bool res = verifier.verifySignature(pk, sig, msgScalar);
        assert(res);
    }

    function test_proof_verify_init() public {
        BBS_Verifier verifier;
        verifier = new BBS_Verifier();
        uint256[] memory disclosed_msg = new uint256[](3);
        disclosed_msg[0] = 2266124219189018131;
        disclosed_msg[1] = 15553430782966677989;
        disclosed_msg[2] = 4743228516788447402;

        uint8[] memory disclosed_indices = new uint8[](3);
        disclosed_indices[0] = 0;
        disclosed_indices[1] = 1;
        disclosed_indices[2] = 5;

        BBS_Verifier.InitProof memory initProof;
        initProof.points[0] = Pairing.G1Point(
            uint256(17705900040482640200318765868397816899423300068827258330107828571873441470719),
            uint256(7713906401864379473036154127800301923576930562959621253303600800199073334118)
        );
        initProof.points[1] = Pairing.G1Point(
            uint256(21727344193746663605105815693486793700736011477614477583899999224491814279994),
            uint256(3107868243865832229708730395440182823160504417487161073020576660932813536129)
        );
        initProof.points[2] = Pairing.G1Point(
            uint256(15259877521667048732653966731531866330870155623999372073511953831671978329220),
            uint256(10346279138881905705140583326619164208036592391424952436660826945178815367429)
        );
        initProof.points[3] = Pairing.G1Point(
            uint256(9450541227839351281812164523351865265510569098677555890572077252104786626690),
            uint256(9197258858130081208441965628507147760561818479091872534935021928583764617680)
        );
        initProof.points[4] = Pairing.G1Point(
            uint256(5816804290213296793101908964222774752394739247046217083058295650122051844227),
            uint256(1590091680226237410825658942611263221992039739303345139797440692938537664171)
        );
        initProof.scalar = uint256(4661402122534330745222086575742781481159552639583525480514127238648290568236);

        BBS_Verifier.InitProof memory init_output =
            verifier.proofVerifyInit(pk, proof, disclosed_msg, disclosed_indices);
        assert(initProof.scalar == init_output.scalar);
        assert(initProof.points[3].X == init_output.points[3].X);
        assert(initProof.points[3].Y == init_output.points[3].Y);
        assert(initProof.points[4].X == init_output.points[4].X);
        assert(initProof.points[4].Y == init_output.points[4].Y);
    }

    function testProofChallengeCalculate() public {
        BBS_Verifier verifier;
        verifier = new BBS_Verifier();
        uint256[] memory disclosed_msg = new uint256[](3);
        disclosed_msg[0] = 2266124219189018131;
        disclosed_msg[1] = 15553430782966677989;
        disclosed_msg[2] = 4743228516788447402;

        uint8[] memory disclosed_indices = new uint8[](3);
        disclosed_indices[0] = 0;
        disclosed_indices[1] = 1;
        disclosed_indices[2] = 5;

        BBS_Verifier.InitProof memory initProof;
        initProof.points[0] = Pairing.G1Point(
            uint256(17705900040482640200318765868397816899423300068827258330107828571873441470719),
            uint256(7713906401864379473036154127800301923576930562959621253303600800199073334118)
        );
        initProof.points[1] = Pairing.G1Point(
            uint256(21727344193746663605105815693486793700736011477614477583899999224491814279994),
            uint256(3107868243865832229708730395440182823160504417487161073020576660932813536129)
        );
        initProof.points[2] = Pairing.G1Point(
            uint256(15259877521667048732653966731531866330870155623999372073511953831671978329220),
            uint256(10346279138881905705140583326619164208036592391424952436660826945178815367429)
        );
        initProof.points[3] = Pairing.G1Point(
            uint256(9450541227839351281812164523351865265510569098677555890572077252104786626690),
            uint256(9197258858130081208441965628507147760561818479091872534935021928583764617680)
        );
        initProof.points[4] = Pairing.G1Point(
            uint256(5816804290213296793101908964222774752394739247046217083058295650122051844227),
            uint256(1590091680226237410825658942611263221992039739303345139797440692938537664171)
        );
        initProof.scalar = uint256(4661402122534330745222086575742781481159552639583525480514127238648290568236);

        uint256 challenge = verifier.proofChallengeCalculate(initProof, disclosed_msg, disclosed_indices);

        assert(challenge == uint256(17070931957668459394149291496811547077907740596908548642717845173554837520766));
    }
}

contract hashToCurve is Test {
    function test_hashToCurve() public view {
        uint256[2] memory res =
            Pairing.hashToPoint("BBS_QUUX-V01-CS02-with-BN254G1_XMD:SHA-256_SVDW_RO_H2G_HM2S_H2S_", "test");
        assert(res[0] == 4687667048072360499873766344051941265352748409069863031676580675735231660684);
        assert(res[1] == 470394146867402188632129722940165669297151995446560861816035625371464676675);
    }
}

contract modCalc is Test {
    function test_mul_mod() public view {
        uint256 res = Pairing.expMod(2, Pairing.PRIME_Q - 1, Pairing.PRIME_Q);
        assert(res == 1);
    }
}

contract sqrt is Test {
    function test_sqrt() public view {
        (uint256 res, bool is_sq) = Pairing.sqrt(121);
        assert(res == 11);
        assert(is_sq);
    }
}
