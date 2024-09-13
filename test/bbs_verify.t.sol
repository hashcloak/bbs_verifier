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
    }

    function test_verify() public {
        BBS_Verifier verifier;
        verifier = new BBS_Verifier();

        bool res = verifier.verifySignature(pk, sig, msgScalar);
        assert(res);
    }
}

contract hashToCurve is Test {
    function test_hashToCurve()  public view {
        uint256[2] memory res = Pairing.hashToPoint("test", "dst");
        assert(res[0] == 10472396393457522110739541980397225556792798958301527074801346528072569881668);
        assert(res[1] == 10229586341858072052103789266835573936791353000004787370356716111864191751005);
    }
}