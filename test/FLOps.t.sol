// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {console} from "forge-std/console.sol";
import {FlopsPaymaster} from "../src/FlopsPaymaster.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {UserOperationLib} from "lib/account-abstraction/contracts/core/UserOperationLib.sol";

import {FlopsAccount} from "../src/FlopsAccount.sol";
import {FlopsAccountFactory} from "../src/FlopsAccountFactory.sol";
import {FlopsData, FlopsCommitment} from "../src/FlopsStructs.sol";
import {Helpers, UserOperationLibHelper} from "./Helpers.sol";

contract FLOpsTest is Helpers {
    function setUp() public {
        setupEOAs();

        entryPoint = deployEntryPoint();
        address[] memory bundlers = new address[](1);
        bundlers[0] = bundlerAddress;
        flopsPaymaster = new FlopsPaymaster(IEntryPoint(address(entryPoint)), owner, bundlers);

        factory = new FlopsAccountFactory(address(flopsPaymaster));

        // Set factory reference in paymaster (circular dependency resolution)
        vm.prank(owner);
        flopsPaymaster.setFactory(address(factory));

        setupAccounts();

        userOperationLibHelper = new UserOperationLibHelper();
    }

    function test_setUp() public {
        // canonical entrypoint address
        assertEq(address(entryPoint), address(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108));

        // contract code was etched
        assertEq(
            entryPoint.getPackedUserOpTypeHash(),
            bytes32(0x29a0bca4af4be3421398da00295e58e6d7de38cb492214754cb6a47507dd6f8e)
        );

        // account addresses are correct
        assertEq(aliceAddress, aliceAcct.owner());
        assertEq(bobAddress, bobAcct.owner());

        // accounts have correct factory reference
        assertEq(aliceAcct.factory(), address(factory));
        assertEq(bobAcct.factory(), address(factory));

        // factory correctly registered accounts
        assertTrue(factory.isFlopsAccount(address(aliceAcct)));
        assertTrue(factory.isFlopsAccount(address(bobAcct)));

        // alice and bob have ETH in their accounts
        assertEq(address(aliceAcct).balance, 100 ether);
        assertEq(address(bobAcct).balance, 100 ether);

        // alice and bob have gas in the entrypoint
        assertEq(entryPoint.balanceOf(address(aliceAcct)), 100 ether);
        assertEq(entryPoint.balanceOf(address(bobAcct)), 100 ether);
    }

    function test_buildUserOp() public {
        address charlie = makeAddr("charlie");
        PackedUserOperation memory userOp = buildUserOp(aliceAcct, charlie, 1 ether, "", alicePrivateKey);
        assertEq(userOp.sender, address(aliceAcct));
        assertEq(userOp.nonce, aliceAcct.getNonce());
        assertEq(userOp.callData, abi.encodeWithSelector(BaseAccount.execute.selector, address(charlie), 1 ether, ""));
        assertEq(userOp.accountGasLimits, bytes32(abi.encodePacked(uint128(100000), uint128(100000))));
        assertEq(userOp.preVerificationGas, 100000);
        assertEq(userOp.gasFees, bytes32(abi.encodePacked(uint128(1000000000), uint128(1000000000))));

        // verify signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        address recovered = ECDSA.recover(userOpHash, userOp.signature);
        assertEq(recovered, aliceAddress);
    }

    // Basic eth transfer using vanilla bundler + BaseAccount
    function test_sendEth() public {
        PackedUserOperation memory userOp = buildUserOp(aliceAcct, charlie, 1 ether, "", alicePrivateKey);
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Call from an EOA to satisfy EntryPoint's nonReentrant modifier
        // Use prank with both msg.sender and tx.origin set to the same EOA
        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        assertEq(address(aliceAcct).balance, 99 ether);
        assertEq(address(charlie).balance, 1 ether);
    }

    function test_buildUserOpWithPaymaster() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        // verify signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        address recovered = ECDSA.recover(userOpHash, userOp.signature);
        assertEq(recovered, aliceAddress);

        // Flop data from bundler
        FlopsData memory flopsData =
            FlopsData({bundleNumber: 1, preTxState: bytes32(0), userOpHash: userOpHash, endOfBundle: false});

        // Append bunder-signed FlopsCommitment to paymasterAndData
        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);

        // Replace paymasterAndData in userOp with the bunder-signed version
        userOp.paymasterAndData = paymasterAndData;

        // Verify user's signature is still valid
        // The paymaster's signature is not part of the userOpHash, so it should still be valid
        // assuming the PAYMASTER_SIG_MAGIC was originally added to the userOp
        userOpHash = entryPoint.getUserOpHash(userOp);
        recovered = ECDSA.recover(userOpHash, userOp.signature);
        assertEq(recovered, aliceAddress);

        // Verify bundler signature
        assertTrue(flopsPaymaster.verifyBundlerSignature(userOp), "Bundler signature not valid");
    }

    // Single ETH transfer using FlopsPaymaster
    function test_sendEthWithPaymaster() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        // Signed user operation
        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        // Flop data from bundler
        FlopsData memory flopsData = FlopsData({
            bundleNumber: 0, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp), endOfBundle: false
        });

        // Append bunder-signed FlopsCommitment to paymasterAndData
        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);

        // Replace paymasterAndData in userOp with the bunder-signed version
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Call from an EOA to satisfy EntryPoint's nonReentrant modifier
        // Use prank with both msg.sender and tx.origin set to the same EOA
        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        assertEq(address(aliceAcct).balance, 99 ether);
        assertEq(address(charlie).balance, 1 ether);
    }

    // Multiple ETH transfers using FlopsPaymaster
    function test_bundleWithPaymaster() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 200000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        // Signed user operation
        PackedUserOperation memory userOp1 =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        PackedUserOperation memory userOp2 =
            buildUserOp(bobAcct, charlie, 1 ether, _staticPaymasterFields, bobPrivateKey);

        // Flop data from bundler
        FlopsData memory flopsData1 = FlopsData({
            bundleNumber: 0, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp1), endOfBundle: false
        });

        FlopsData memory flopsData2 = FlopsData({
            bundleNumber: 0,
            preTxState: flopsPaymaster.nextRollingHash(userOp1),
            userOpHash: entryPoint.getUserOpHash(userOp2),
            endOfBundle: true
        });

        // Append bunder-signed FlopsCommitment to paymasterAndData
        bytes memory paymasterAndData1 =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData1, bundlerPrivateKey);

        bytes memory paymasterAndData2 =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData2, bundlerPrivateKey);

        // Replace paymasterAndData in userOp with the bunder-signed version
        userOp1.paymasterAndData = paymasterAndData1;
        userOp2.paymasterAndData = paymasterAndData2;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](2);
        userOps[0] = userOp1;
        userOps[1] = userOp2;

        // Call from an EOA to satisfy EntryPoint's nonReentrant modifier
        // Use prank with both msg.sender and tx.origin set to the same EOA
        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        assertEq(address(aliceAcct).balance, 99 ether);
        assertEq(address(bobAcct).balance, 99 ether);
        assertEq(address(charlie).balance, 2 ether);
    }

    // ============ UNHAPPY PATH TESTS - BUNDLE BREAKING SCENARIOS ============

    // Test 1: Wrong bundle number breaks the bundle
    function test_wrongBundleNumber_breaksBundle() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        // Use WRONG bundle number (999 instead of 0)
        FlopsData memory flopsData = FlopsData({
            bundleNumber: 999, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp), endOfBundle: false
        });

        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Bundle should not be broken before execution
        assertFalse(flopsPaymaster.bundleBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Bundle should be marked as broken
        assertTrue(flopsPaymaster.bundleBroken());
        // Transaction should not have executed (charlie didn't receive funds)
        assertEq(address(charlie).balance, 0 ether);
    }

    // Test 2: Incorrect preTxState (rolling hash mismatch) breaks bundle
    function test_incorrectPreTxState_breaksBundle() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        // Use WRONG preTxState (some random hash instead of bytes32(0))
        FlopsData memory flopsData = FlopsData({
            bundleNumber: 0,
            preTxState: keccak256("wrong state"),
            userOpHash: entryPoint.getUserOpHash(userOp),
            endOfBundle: false
        });

        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        assertFalse(flopsPaymaster.bundleBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Bundle should be marked as broken
        assertTrue(flopsPaymaster.bundleBroken());
        // Transaction should not have executed
        assertEq(address(charlie).balance, 0 ether);
    }

    // Test 3a: Invalid bundler signature (non-approved bundler) breaks bundle
    function test_nonApprovedBundler_breaksBundle() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        FlopsData memory flopsData = FlopsData({
            bundleNumber: 0, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp), endOfBundle: false
        });

        // Sign with a different private key (not the approved bundler)
        (, uint256 evilPrivateKey) = makeAddrAndKey("evilBundler");
        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, evilPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        assertFalse(flopsPaymaster.bundleBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Bundle should be marked as broken
        assertTrue(flopsPaymaster.bundleBroken());
        assertEq(address(charlie).balance, 0 ether);
    }

    // Test 3b: Corrupted signature causes revert (ECDSA validation failure)
    function test_corruptedSignature_causesRevert() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        FlopsData memory flopsData = FlopsData({
            bundleNumber: 0, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp), endOfBundle: false
        });

        // Build valid paymasterAndData
        bytes32 commitmentHash = flopsPaymaster.computeBundlerCommitHash(flopsData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(bundlerPrivateKey, commitmentHash);

        // Corrupt the signature by flipping r
        r = bytes32(uint256(r) ^ 0xFF);
        bytes memory corruptedSignature = abi.encodePacked(r, s, v);

        FlopsCommitment memory flopsCommitment = FlopsCommitment({data: flopsData, signature: corruptedSignature});
        bytes memory paymasterSignature = abi.encode(flopsCommitment);
        bytes memory paymasterSignatureWithLength = userOperationLibHelper.encodePaymasterSignature(paymasterSignature);
        bytes memory paymasterAndData =
            abi.encodePacked(paymaster, verificationGasLimit, postOpGasLimit, paymasterSignatureWithLength);

        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Corrupted signature causes ECDSA revert during validation
        vm.prank(bundlerAddress, bundlerAddress);
        vm.expectRevert();
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Transaction didn't execute
        assertEq(address(charlie).balance, 0 ether);
    }

    // Test 3c: Mismatched userOpHash in commitment breaks bundle
    function test_mismatchedUserOpHash_breaksBundle() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        // Use a WRONG userOpHash in the commitment
        FlopsData memory flopsData = FlopsData({
            bundleNumber: 0,
            preTxState: bytes32(0),
            userOpHash: keccak256("wrong hash"), // Wrong hash!
            endOfBundle: false
        });

        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        assertFalse(flopsPaymaster.bundleBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Bundle should be marked as broken
        assertTrue(flopsPaymaster.bundleBroken());
        assertEq(address(charlie).balance, 0 ether);
    }

    // Test 4: Non-FlopsAccount sender breaks bundle
    function test_nonFlopsAccountSender_breaksBundle() public {
        // Deploy a FlopsAccount-like contract but don't register it with the factory
        (address fakeOwner, uint256 fakePrivateKey) = makeAddrAndKey("fakeOwner");

        // Deploy an account using the factory but for a different owner
        // Then use it but it won't be in Alice/Bob's known accounts
        FlopsAccount fakeAccount = FlopsAccount(payable(factory.createAccount(fakeOwner)));
        vm.deal(address(fakeAccount), 100 ether);
        entryPoint.depositTo{value: 100 ether}(address(fakeAccount));

        // Now unregister it from the factory to simulate a non-FlopsAccount
        // Since we can't actually unregister, we'll test with a fresh factory instance
        FlopsAccountFactory fakeFactory = new FlopsAccountFactory(address(flopsPaymaster));
        FlopsAccount unregisteredAcct = new FlopsAccount(fakeOwner, address(fakeFactory), address(flopsPaymaster));
        vm.deal(address(unregisteredAcct), 100 ether);
        entryPoint.depositTo{value: 100 ether}(address(unregisteredAcct));

        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        // Build userOp from unregistered account
        PackedUserOperation memory userOp =
            buildUserOp(unregisteredAcct, charlie, 1 ether, _staticPaymasterFields, fakePrivateKey);

        FlopsData memory flopsData = FlopsData({
            bundleNumber: 0, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp), endOfBundle: false
        });

        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        assertFalse(flopsPaymaster.bundleBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Bundle should be marked as broken (account not registered with main factory)
        assertTrue(flopsPaymaster.bundleBroken());
        assertEq(address(charlie).balance, 0 ether);
    }

    // Test 5: Execution failure doesn't break bundle (note: postOp not called with empty context)
    // This test demonstrates that execution failures alone don't break bundles
    // because _postOp is only called when context is non-empty (per ERC-4337 spec)
    function test_executionFailure_doesNotBreakBundle() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        // Try to send MORE ether than Alice has
        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 200 ether, _staticPaymasterFields, alicePrivateKey);

        FlopsData memory flopsData = FlopsData({
            bundleNumber: 0, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp), endOfBundle: false
        });

        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        assertFalse(flopsPaymaster.bundleBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Bundle is NOT broken because postOp isn't called with empty context
        // The rolling hash still advanced during validation
        assertFalse(flopsPaymaster.bundleBroken());
        // Charlie should not have received any funds
        assertEq(address(charlie).balance, 0 ether);
        // Alice's balance should remain unchanged
        assertEq(address(aliceAcct).balance, 100 ether);
    }

    // Test 6: Cascade effect - once bundle is broken, subsequent operations also fail validation
    function test_cascadeEffect_brokenBundlePreventsExecution() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 200000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        // First operation with wrong preTxState (will break bundle)
        PackedUserOperation memory userOp1 =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        FlopsData memory flopsData1 = FlopsData({
            bundleNumber: 0,
            preTxState: keccak256("wrong"), // Wrong state!
            userOpHash: entryPoint.getUserOpHash(userOp1),
            endOfBundle: false
        });

        bytes memory paymasterAndData1 =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData1, bundlerPrivateKey);
        userOp1.paymasterAndData = paymasterAndData1;

        // Second operation - expects rollingHash to have advanced, but it won't have
        PackedUserOperation memory userOp2 =
            buildUserOp(bobAcct, charlie, 1 ether, _staticPaymasterFields, bobPrivateKey);

        // This expects the rolling hash to have advanced from userOp1, but it won't because userOp1 broke the bundle
        bytes32 expectedRollingHashAfterOp1 = flopsPaymaster.nextRollingHash(userOp1);

        FlopsData memory flopsData2 = FlopsData({
            bundleNumber: 0,
            preTxState: expectedRollingHashAfterOp1, // This will be wrong because op1 broke the bundle
            userOpHash: entryPoint.getUserOpHash(userOp2),
            endOfBundle: true
        });

        bytes memory paymasterAndData2 =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData2, bundlerPrivateKey);
        userOp2.paymasterAndData = paymasterAndData2;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](2);
        userOps[0] = userOp1;
        userOps[1] = userOp2;

        assertFalse(flopsPaymaster.bundleBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Bundle should be broken
        assertTrue(flopsPaymaster.bundleBroken());
        // Neither transaction should have executed
        assertEq(address(charlie).balance, 0 ether);
        assertEq(address(aliceAcct).balance, 100 ether);
        assertEq(address(bobAcct).balance, 100 ether);
    }

    // Test 7: Multi-op bundle with mid-bundle failure
    // Both operations fail because bundle is broken during validation before any execution
    function test_midBundleFailure_validationBreaksBundle() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 200000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        // First operation - VALID
        PackedUserOperation memory userOp1 =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);
        userOp1.paymasterAndData = buildPaymasterAndData(
            paymaster,
            verificationGasLimit,
            postOpGasLimit,
            FlopsData({
                bundleNumber: 0,
                preTxState: bytes32(0),
                userOpHash: entryPoint.getUserOpHash(userOp1),
                endOfBundle: false
            }),
            bundlerPrivateKey
        );

        // Second operation - INVALID (wrong preTxState, will break bundle during validation)
        PackedUserOperation memory userOp2 =
            buildUserOp(bobAcct, charlie, 1 ether, _staticPaymasterFields, bobPrivateKey);
        userOp2.paymasterAndData = buildPaymasterAndData(
            paymaster,
            verificationGasLimit,
            postOpGasLimit,
            FlopsData({
                bundleNumber: 0,
                preTxState: bytes32(0),
                userOpHash: entryPoint.getUserOpHash(userOp2),
                endOfBundle: true
            }),
            bundlerPrivateKey
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](2);
        userOps[0] = userOp1;
        userOps[1] = userOp2;

        assertFalse(flopsPaymaster.bundleBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Bundle should be broken (second op broke it during validation)
        assertTrue(flopsPaymaster.bundleBroken());
        // Neither operation executed because bundle was broken before execution phase
        assertEq(address(charlie).balance, 0 ether);
        assertEq(address(aliceAcct).balance, 100 ether);
        assertEq(address(bobAcct).balance, 100 ether);
    }

    // Test 8: Bundle recovery - next bundle works after broken bundle is finalized
    function test_bundleRecovery_afterBrokenBundle() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        // === BUNDLE 0: Break it ===
        PackedUserOperation memory userOp1 =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        FlopsData memory flopsData1 = FlopsData({
            bundleNumber: 0,
            preTxState: keccak256("wrong"), // Wrong state - will break bundle
            userOpHash: entryPoint.getUserOpHash(userOp1),
            endOfBundle: true
        });

        bytes memory paymasterAndData1 =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData1, bundlerPrivateKey);
        userOp1.paymasterAndData = paymasterAndData1;

        PackedUserOperation[] memory userOps1 = new PackedUserOperation[](1);
        userOps1[0] = userOp1;

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps1, payable(bundlerAddress));

        // Verify bundle 0 is broken
        assertTrue(flopsPaymaster.bundleBroken(0));
        assertEq(flopsPaymaster.currentBundleNumber(), 0);
        assertEq(address(charlie).balance, 0 ether);

        // Finalize the broken bundle (move to next bundle)
        vm.prank(owner);
        flopsPaymaster.finalizeCurrentBundle();

        // Verify we're on bundle 1 now
        assertEq(flopsPaymaster.currentBundleNumber(), 1);
        assertFalse(flopsPaymaster.bundleBroken()); // Current bundle (1) is not broken
        assertTrue(flopsPaymaster.bundleBroken(0)); // But bundle 0 is still marked as broken

        // === BUNDLE 1: Should work correctly ===
        PackedUserOperation memory userOp2 =
            buildUserOp(bobAcct, charlie, 2 ether, _staticPaymasterFields, bobPrivateKey);

        FlopsData memory flopsData2 = FlopsData({
            bundleNumber: 1, // New bundle number
            preTxState: bytes32(0), // Fresh start
            userOpHash: entryPoint.getUserOpHash(userOp2),
            endOfBundle: true
        });

        bytes memory paymasterAndData2 =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData2, bundlerPrivateKey);
        userOp2.paymasterAndData = paymasterAndData2;

        PackedUserOperation[] memory userOps2 = new PackedUserOperation[](1);
        userOps2[0] = userOp2;

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps2, payable(bundlerAddress));

        // Verify bundle 1 succeeded
        assertFalse(flopsPaymaster.bundleBroken(1));
        assertEq(address(charlie).balance, 2 ether);
        assertEq(address(bobAcct).balance, 98 ether);
    }
}
