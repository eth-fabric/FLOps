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
import {BundlerManager} from "../src/BundlerManager.sol";
import {FlopsData, FlopsCommitment} from "../src/FlopsStructs.sol";
import {Helpers, UserOperationLibHelper} from "./Helpers.sol";

contract FLOpsTest is Helpers {
    function setUp() public {
        setupEOAs();

        entryPoint = deployEntryPoint();
        address[] memory bundlers = new address[](1);
        bundlers[0] = bundlerAddress;
        BundlerManager bundlerManager = new BundlerManager(owner, bundlers);
        flopsPaymaster = new FlopsPaymaster(IEntryPoint(address(entryPoint)), owner, address(bundlerManager));

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
        FlopsData memory flopsData = FlopsData({blockNumber: 1, preTxState: bytes32(0), userOpHash: userOpHash});

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
        FlopsData memory flopsData =
            FlopsData({blockNumber: 1, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp)});

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
        FlopsData memory flopsData1 =
            FlopsData({blockNumber: 1, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp1)});

        FlopsData memory flopsData2 = FlopsData({
            blockNumber: 1,
            preTxState: flopsPaymaster.nextRollingHash(userOp1),
            userOpHash: entryPoint.getUserOpHash(userOp2)
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

    // ============ UNHAPPY PATH TESTS - BLOCK BREAKING SCENARIOS ============

    // Test 1: Wrong block number breaks the block
    function test_wrongBlockNumber_breaksBlock() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        // Use WRONG block number (999 instead of current block)
        FlopsData memory flopsData =
            FlopsData({blockNumber: 999, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp)});

        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Block should not be broken before execution
        assertFalse(flopsPaymaster.blockBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Block should be marked as broken
        assertTrue(flopsPaymaster.blockBroken());
        // Transaction should not have executed (charlie didn't receive funds)
        assertEq(address(charlie).balance, 0 ether);
    }

    // Test 2: Incorrect preTxState (rolling hash mismatch) breaks block
    function test_incorrectPreTxState_breaksBlock() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        // Use WRONG preTxState (some random hash instead of bytes32(0))
        FlopsData memory flopsData = FlopsData({
            blockNumber: 1, preTxState: keccak256("wrong state"), userOpHash: entryPoint.getUserOpHash(userOp)
        });

        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        assertFalse(flopsPaymaster.blockBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Block should be marked as broken
        assertTrue(flopsPaymaster.blockBroken());
        // Transaction should not have executed
        assertEq(address(charlie).balance, 0 ether);
    }

    // Test 3a: Invalid bundler signature (non-approved bundler) breaks block
    function test_nonApprovedBundler_breaksBlock() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        FlopsData memory flopsData =
            FlopsData({blockNumber: 1, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp)});

        // Sign with a different private key (not the approved bundler)
        (, uint256 evilPrivateKey) = makeAddrAndKey("evilBundler");
        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, evilPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        assertFalse(flopsPaymaster.blockBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Block should be marked as broken
        assertTrue(flopsPaymaster.blockBroken());
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
            blockNumber: uint64(block.number), preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp)
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
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Block should be marked as broken
        assertTrue(flopsPaymaster.blockBroken());

        // Transaction didn't execute
        assertEq(address(charlie).balance, 0 ether);
    }

    // Test 3c: Mismatched userOpHash in commitment breaks block
    function test_mismatchedUserOpHash_breaksBlock() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        // Use a WRONG userOpHash in the commitment
        FlopsData memory flopsData = FlopsData({
            blockNumber: 1,
            preTxState: bytes32(0),
            userOpHash: keccak256("wrong hash") // Wrong hash!
        });

        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        assertFalse(flopsPaymaster.blockBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Block should be marked as broken
        assertTrue(flopsPaymaster.blockBroken());
        assertEq(address(charlie).balance, 0 ether);
    }

    // Test 4: Non-FlopsAccount sender breaks block
    function test_nonFlopsAccountSender_breaksBlock() public {
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

        FlopsData memory flopsData =
            FlopsData({blockNumber: 1, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp)});

        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        assertFalse(flopsPaymaster.blockBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Block should be marked as broken (account not registered with main factory)
        assertTrue(flopsPaymaster.blockBroken());
        assertEq(address(charlie).balance, 0 ether);
    }

    // Test 5: Execution failure breaks block
    function test_executionFailure_breaksBlock() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        // Try to send MORE ether than Alice has
        PackedUserOperation memory userOp =
            buildUserOp(aliceAcct, charlie, 200 ether, _staticPaymasterFields, alicePrivateKey);

        FlopsData memory flopsData =
            FlopsData({blockNumber: 1, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp)});

        bytes memory paymasterAndData =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData, bundlerPrivateKey);
        userOp.paymasterAndData = paymasterAndData;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        assertFalse(flopsPaymaster.blockBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Block should be marked as broken
        assertTrue(flopsPaymaster.blockBroken());
        // Charlie should not have received any funds
        assertEq(address(charlie).balance, 0 ether);
        // Alice's balance should remain unchanged
        assertEq(address(aliceAcct).balance, 100 ether);
    }

    // Test 6: Cascade effect - once block is broken, subsequent operations also fail validation
    function test_cascadeEffect_brokenBlockPreventsExecution() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 200000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        // First operation with wrong preTxState (will break block)
        PackedUserOperation memory userOp1 =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        FlopsData memory flopsData1 = FlopsData({
            blockNumber: 1,
            preTxState: keccak256("wrong"), // Wrong state!
            userOpHash: entryPoint.getUserOpHash(userOp1)
        });

        bytes memory paymasterAndData1 =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData1, bundlerPrivateKey);
        userOp1.paymasterAndData = paymasterAndData1;

        // Second operation - expects rollingHash to have advanced, but it won't have
        PackedUserOperation memory userOp2 =
            buildUserOp(bobAcct, charlie, 1 ether, _staticPaymasterFields, bobPrivateKey);

        // This expects the rolling hash to have advanced from userOp1, but it won't because userOp1 broke the block
        bytes32 expectedRollingHashAfterOp1 = flopsPaymaster.nextRollingHash(userOp1);

        FlopsData memory flopsData2 = FlopsData({
            blockNumber: 1,
            preTxState: expectedRollingHashAfterOp1, // This will be wrong because op1 broke the block
            userOpHash: entryPoint.getUserOpHash(userOp2)
        });

        bytes memory paymasterAndData2 =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData2, bundlerPrivateKey);
        userOp2.paymasterAndData = paymasterAndData2;

        PackedUserOperation[] memory userOps = new PackedUserOperation[](2);
        userOps[0] = userOp1;
        userOps[1] = userOp2;

        assertFalse(flopsPaymaster.blockBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Block should be broken
        assertTrue(flopsPaymaster.blockBroken());
        // Neither transaction should have executed
        assertEq(address(charlie).balance, 0 ether);
        assertEq(address(aliceAcct).balance, 100 ether);
        assertEq(address(bobAcct).balance, 100 ether);
    }

    // Test 7: Multi-op block with mid-block failure
    // Both operations fail because block is broken during validation before any execution
    function test_midBlockFailure_validationBreaksBlock() public {
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
            FlopsData({blockNumber: 1, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp1)}),
            bundlerPrivateKey
        );

        // Second operation - INVALID (wrong preTxState, will break block during validation)
        PackedUserOperation memory userOp2 =
            buildUserOp(bobAcct, charlie, 1 ether, _staticPaymasterFields, bobPrivateKey);
        userOp2.paymasterAndData = buildPaymasterAndData(
            paymaster,
            verificationGasLimit,
            postOpGasLimit,
            FlopsData({blockNumber: 1, preTxState: bytes32(0), userOpHash: entryPoint.getUserOpHash(userOp2)}),
            bundlerPrivateKey
        );

        PackedUserOperation[] memory userOps = new PackedUserOperation[](2);
        userOps[0] = userOp1;
        userOps[1] = userOp2;

        assertFalse(flopsPaymaster.blockBroken());

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps, payable(bundlerAddress));

        // Block should be broken (second op broke it during validation)
        assertTrue(flopsPaymaster.blockBroken());
        // Neither operation executed because block was broken before execution phase
        assertEq(address(charlie).balance, 0 ether);
        assertEq(address(aliceAcct).balance, 100 ether);
        assertEq(address(bobAcct).balance, 100 ether);
    }

    // Test 8: Block recovery - operations in different blocks work independently
    function test_blockRecovery_afterBrokenBlock() public {
        address paymaster = address(flopsPaymaster);
        uint128 verificationGasLimit = 100000;
        uint128 postOpGasLimit = 100000;
        bytes memory _staticPaymasterFields =
            staticPaymasterFieldsWithMagicPlaceholder(paymaster, verificationGasLimit, postOpGasLimit);

        // === BLOCK 1: Break it ===
        PackedUserOperation memory userOp1 =
            buildUserOp(aliceAcct, charlie, 1 ether, _staticPaymasterFields, alicePrivateKey);

        FlopsData memory flopsData1 = FlopsData({
            blockNumber: 1,
            preTxState: keccak256("wrong"), // Wrong state - will break block
            userOpHash: entryPoint.getUserOpHash(userOp1)
        });

        bytes memory paymasterAndData1 =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData1, bundlerPrivateKey);
        userOp1.paymasterAndData = paymasterAndData1;

        PackedUserOperation[] memory userOps1 = new PackedUserOperation[](1);
        userOps1[0] = userOp1;

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps1, payable(bundlerAddress));

        // Verify block 1 is broken
        assertTrue(flopsPaymaster.blockBroken(1));
        assertEq(address(charlie).balance, 0 ether);

        // === BLOCK 2: Should work correctly (different block) ===
        // Advance to next block
        vm.roll(block.number + 1);

        PackedUserOperation memory userOp2 =
            buildUserOp(bobAcct, charlie, 2 ether, _staticPaymasterFields, bobPrivateKey);

        FlopsData memory flopsData2 = FlopsData({
            blockNumber: 2, // New block number
            preTxState: bytes32(0), // Fresh start
            userOpHash: entryPoint.getUserOpHash(userOp2)
        });

        bytes memory paymasterAndData2 =
            buildPaymasterAndData(paymaster, verificationGasLimit, postOpGasLimit, flopsData2, bundlerPrivateKey);
        userOp2.paymasterAndData = paymasterAndData2;

        PackedUserOperation[] memory userOps2 = new PackedUserOperation[](1);
        userOps2[0] = userOp2;

        vm.prank(bundlerAddress, bundlerAddress);
        entryPoint.handleOps(userOps2, payable(bundlerAddress));

        // Verify block 2 succeeded
        assertFalse(flopsPaymaster.blockBroken(2));
        assertTrue(flopsPaymaster.blockBroken(1)); // Block 1 still broken
        assertEq(address(charlie).balance, 2 ether);
        assertEq(address(bobAcct).balance, 98 ether);
    }
}
