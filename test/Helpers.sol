// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test} from "forge-std/Test.sol";
import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {BasePaymaster} from "lib/account-abstraction/contracts/core/BasePaymaster.sol";
import {BaseAccount} from "lib/account-abstraction/contracts/core/BaseAccount.sol";
import {EntryPoint} from "lib/account-abstraction/contracts/core/EntryPoint.sol";
import {UserOperationLib} from "lib/account-abstraction/contracts/core/UserOperationLib.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";

import {FlopsPaymaster} from "../src/FlopsPaymaster.sol";
import {FlopsAccountFactory} from "../src/FlopsAccountFactory.sol";
import {FlopsAccount} from "../src/FlopsAccount.sol";
import {BundleInfo, FlopsData, FlopsCommitment} from "../src/FlopsStructs.sol";

contract Helpers is Test {
    EntryPoint public entryPoint;
    FlopsPaymaster public flopsPaymaster;
    FlopsAccountFactory public factory;

    uint256 public alicePrivateKey;
    uint256 public bobPrivateKey;
    uint256 public bundlerPrivateKey;
    address public bundlerAddress;
    address public aliceAddress;
    address public bobAddress;
    address public owner = makeAddr("owner");

    FlopsAccount public aliceAcct;
    FlopsAccount public bobAcct;

    // Force to canonical entrypoint address, todo use create2 deployer
    function deployEntryPoint() public returns (EntryPoint) {
        EntryPoint _entryPoint = new EntryPoint();
        address payable target = payable(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
        vm.etch(target, address(_entryPoint).code);
        return EntryPoint(target);
    }

    function setupAccounts() public {
        // Create EOAs
        (aliceAddress, alicePrivateKey) = makeAddrAndKey("alice");
        (bobAddress, bobPrivateKey) = makeAddrAndKey("bob");
        (bundlerAddress, bundlerPrivateKey) = makeAddrAndKey("bundler");

        // Create smart accounts
        aliceAcct = FlopsAccount(payable(factory.createAccount(aliceAddress)));
        bobAcct = FlopsAccount(payable(factory.createAccount(bobAddress)));

        // Fund smart accounts with ETH
        vm.deal(address(aliceAcct), 100 ether);
        vm.deal(address(bobAcct), 100 ether);

        // Pre-fill gas at entrypoint for smart accounts
        entryPoint.depositTo{value: 100 ether}(address(aliceAcct));
        entryPoint.depositTo{value: 100 ether}(address(bobAcct));
    }

    /**
     * Utility function to encode paymasterAndData for FLOps
     * @param paymaster The paymaster address
     * @param verificationGasLimit Gas limit for validation
     * @param postOpGasLimit Gas limit for postOp
     * @param flopsData The FLOps-specific data
     * @return Properly encoded paymasterAndData bytes
     */
    function encodePaymasterAndData(
        address paymaster,
        uint128 verificationGasLimit,
        uint128 postOpGasLimit,
        FlopsData memory flopsData
    ) public pure returns (bytes memory) {
        bytes memory encodedFlopsData = abi.encode(flopsData);
        return abi.encodePacked(paymaster, verificationGasLimit, postOpGasLimit, encodedFlopsData);
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
}
