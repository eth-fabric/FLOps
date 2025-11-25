// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console2} from "forge-std/Test.sol";
import {FLOpsPaymaster} from "../src/FLOpsPaymaster.sol";
import {AtomicEntryPoint} from "../src/AtomicEntryPoint.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";

import {BasicAccount} from "./BasicAccount.sol";

contract FLOpsTest is Test {
    EntryPoint public entryPoint;
    FLOpsPaymaster public flopsPaymaster;
    AtomicEntryPoint public atomicEntryPoint;

    BasicAccount public alice;
    BasicAccount public bob;
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
        flopsPaymaster = new FLOpsPaymaster(IEntryPoint(address(entryPoint)), owner);
        atomicEntryPoint = new AtomicEntryPoint(address(entryPoint), address(flopsPaymaster));

        vm.prank(owner);
        flopsPaymaster.setAtomicEntryPoint(address(atomicEntryPoint));

        // Setup smart accounts with ETH
        alice = new BasicAccount(makeAddr("alice"));
        vm.deal(address(alice), 100 ether);
        bob = new BasicAccount(makeAddr("bob"));
        vm.deal(address(bob), 100 ether);

        // Pre-fill gas at entrypoint for smart accounts
        entryPoint.depositTo{value: 100 ether}(address(alice));
        entryPoint.depositTo{value: 100 ether}(address(bob));
    }

    function test_setUp() public {
        // canonical entrypoint address
        assertEq(address(entryPoint), address(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108));

        // contract code was etched
        assertEq(
            entryPoint.getPackedUserOpTypeHash(),
            bytes32(0x29a0bca4af4be3421398da00295e58e6d7de38cb492214754cb6a47507dd6f8e)
        );

        // setAtomicEntryPoint works
        assertEq(address(flopsPaymaster.atomicEntryPoint()), address(atomicEntryPoint));

        // alice and bob have ETH in their accounts
        assertEq(address(alice).balance, 100 ether);
        assertEq(address(bob).balance, 100 ether);

        // alice and bob have gas in the entrypoint
        assertEq(entryPoint.balanceOf(address(alice)), 100 ether);
        assertEq(entryPoint.balanceOf(address(bob)), 100 ether);
    }
}
