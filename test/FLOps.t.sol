// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {FlopsPaymaster} from "../src/FlopsPaymaster.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {FlopsAccount} from "../src/FlopsAccount.sol";
import {FlopsAccountFactory} from "../src/FlopsAccountFactory.sol";
import {Helpers} from "./Helpers.sol";

contract FLOpsTest is Helpers {
    function setUp() public {
        entryPoint = deployEntryPoint();
        address[] memory bundlers = new address[](1);
        bundlers[0] = bundlerAddress;
        flopsPaymaster = new FlopsPaymaster(IEntryPoint(address(entryPoint)), owner, bundlers);

        factory = new FlopsAccountFactory(address(flopsPaymaster));

        // Set factory reference in paymaster (circular dependency resolution)
        vm.prank(owner);
        flopsPaymaster.setFactory(address(factory));

        setupAccounts();
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
    function test_sendETH() public {
        address charlie = makeAddr("charlie");
        PackedUserOperation memory userOp = buildUserOp(aliceAcct, charlie, 1 ether, "", alicePrivateKey);
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Call from an EOA to satisfy EntryPoint's nonReentrant modifier
        // Use prank with both msg.sender and tx.origin set to the same EOA
        address bundler = makeAddr("bundler");
        vm.prank(bundler, bundler);
        entryPoint.handleOps(userOps, payable(makeAddr("beneficiary")));

        assertEq(address(aliceAcct).balance, 99 ether);
        assertEq(address(charlie).balance, 1 ether);
    }
}
