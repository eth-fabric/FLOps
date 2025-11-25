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

contract FLOpsTest is Test {
    EntryPoint public entryPoint;
    FlopsPaymaster public flopsPaymaster;
    FlopsAccountFactory public factory;

    uint256 public alicePrivateKey;
    uint256 public bobPrivateKey;
    address public aliceAddress;
    address public bobAddress;
    FlopsAccount public alice;
    FlopsAccount public bob;
    address public owner;

    // Force to canonical entrypoint address, todo use create2 deployer
    function deployEntryPoint() public returns (EntryPoint) {
        EntryPoint _entryPoint = new EntryPoint();
        address payable target = payable(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
        vm.etch(target, address(_entryPoint).code);
        return EntryPoint(target);
    }

    function setUp() public {
        owner = makeAddr("owner");
        entryPoint = deployEntryPoint();
        flopsPaymaster = new FlopsPaymaster(IEntryPoint(address(entryPoint)), owner);
        factory = new FlopsAccountFactory();

        // Create smart accounts
        (aliceAddress, alicePrivateKey) = makeAddrAndKey("alice");
        (bobAddress, bobPrivateKey) = makeAddrAndKey("bob");
        alice = FlopsAccount(payable(factory.createAccount(aliceAddress)));
        bob = FlopsAccount(payable(factory.createAccount(bobAddress)));

        // Fund smart accounts with ETH
        vm.deal(address(alice), 100 ether);
        vm.deal(address(bob), 100 ether);

        // Pre-fill gas at entrypoint for smart accounts
        entryPoint.depositTo{value: 100 ether}(address(alice));
        entryPoint.depositTo{value: 100 ether}(address(bob));
    }

    function buildUserOp(
        FlopsAccount account,
        address to,
        uint256 value,
        bytes memory paymasterAndData,
        uint256 privateKey
    ) public returns (PackedUserOperation memory) {
        assertEq(vm.addr(privateKey), account.owner());
        PackedUserOperation memory userOp = PackedUserOperation({
            sender: address(account),
            nonce: account.getNonce(),
            initCode: "",
            callData: abi.encodeWithSelector(BaseAccount.execute.selector, to, value, ""),
            accountGasLimits: bytes32(abi.encodePacked(uint128(100000), uint128(100000))),
            preVerificationGas: 100000,
            gasFees: bytes32(abi.encodePacked(uint128(1000000000), uint128(1000000000))),
            paymasterAndData: paymasterAndData,
            signature: ""
        });

        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, userOpHash);
        bytes memory signature = abi.encodePacked(r, s, v);
        userOp.signature = signature;
        return userOp;
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
        assertEq(aliceAddress, alice.owner());
        assertEq(bobAddress, bob.owner());

        // accounts have correct factory reference
        assertEq(alice.factory(), address(factory));
        assertEq(bob.factory(), address(factory));

        // factory correctly registered accounts
        assertTrue(factory.isFlopsAccount(address(alice)));
        assertTrue(factory.isFlopsAccount(address(bob)));

        // alice and bob have ETH in their accounts
        assertEq(address(alice).balance, 100 ether);
        assertEq(address(bob).balance, 100 ether);

        // alice and bob have gas in the entrypoint
        assertEq(entryPoint.balanceOf(address(alice)), 100 ether);
        assertEq(entryPoint.balanceOf(address(bob)), 100 ether);
    }

    function test_buildUserOp() public {
        address charlie = makeAddr("charlie");
        PackedUserOperation memory userOp = buildUserOp(alice, charlie, 1 ether, "", alicePrivateKey);
        assertEq(userOp.sender, address(alice));
        assertEq(userOp.nonce, alice.getNonce());
        assertEq(userOp.callData, abi.encodeWithSelector(BaseAccount.execute.selector, address(charlie), 1 ether, ""));
        assertEq(userOp.accountGasLimits, bytes32(abi.encodePacked(uint128(100000), uint128(100000))));
        assertEq(userOp.preVerificationGas, 100000);
        assertEq(userOp.gasFees, bytes32(abi.encodePacked(uint128(1000000000), uint128(1000000000))));

        // verify signature
        bytes32 userOpHash = entryPoint.getUserOpHash(userOp);
        address recovered = ECDSA.recover(userOpHash, userOp.signature);
        assertEq(recovered, aliceAddress);
    }

    function test_sendETH() public {
        address charlie = makeAddr("charlie");
        PackedUserOperation memory userOp = buildUserOp(alice, charlie, 1 ether, "", alicePrivateKey);
        PackedUserOperation[] memory userOps = new PackedUserOperation[](1);
        userOps[0] = userOp;

        // Call from an EOA to satisfy EntryPoint's nonReentrant modifier
        // Use prank with both msg.sender and tx.origin set to the same EOA
        address bundler = makeAddr("bundler");
        vm.prank(bundler, bundler);
        entryPoint.handleOps(userOps, payable(makeAddr("beneficiary")));

        assertEq(address(alice).balance, 99 ether);
        assertEq(address(charlie).balance, 1 ether);
    }
}
