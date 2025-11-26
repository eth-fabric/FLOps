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
import {FlopsData, FlopsCommitment} from "../src/FlopsStructs.sol";

// Wrapper contract to deal with memory<>calldata conversions
contract UserOperationLibHelper {
    function encodePaymasterSignature(bytes calldata paymasterSignature) public returns (bytes memory) {
        return UserOperationLib.encodePaymasterSignature(paymasterSignature);
    }

    function getPaymasterSignature(bytes calldata paymasterAndData) public returns (bytes memory) {
        return UserOperationLib.getPaymasterSignature(paymasterAndData);
    }
}

contract Helpers is Test {
    EntryPoint public entryPoint;
    FlopsPaymaster public flopsPaymaster;
    FlopsAccountFactory public factory;
    UserOperationLibHelper public userOperationLibHelper;

    uint256 public alicePrivateKey;
    uint256 public bobPrivateKey;
    uint256 public bundlerPrivateKey;
    address public bundlerAddress;
    address public aliceAddress;
    address public bobAddress;
    address public owner = makeAddr("owner");
    address public charlie = makeAddr("charlie");

    FlopsAccount public aliceAcct;
    FlopsAccount public bobAcct;

    // Force to canonical entrypoint address, todo use create2 deployer
    function deployEntryPoint() public returns (EntryPoint) {
        EntryPoint _entryPoint = new EntryPoint();
        address payable target = payable(0x4337084D9E255Ff0702461CF8895CE9E3b5Ff108);
        vm.etch(target, address(_entryPoint).code);
        return EntryPoint(target);
    }

    function setupEOAs() public {
        // Create EOAs
        (aliceAddress, alicePrivateKey) = makeAddrAndKey("alice");
        (bobAddress, bobPrivateKey) = makeAddrAndKey("bob");
        (bundlerAddress, bundlerPrivateKey) = makeAddrAndKey("bundler");
    }

    function setupAccounts() public {
        // Create smart accounts
        aliceAcct = FlopsAccount(payable(factory.createAccount(aliceAddress)));
        bobAcct = FlopsAccount(payable(factory.createAccount(bobAddress)));

        // Fund smart accounts with ETH
        vm.deal(address(aliceAcct), 100 ether);
        vm.deal(address(bobAcct), 100 ether);

        // Pre-fill gas at entrypoint for smart accounts
        entryPoint.depositTo{value: 100 ether}(address(aliceAcct));
        entryPoint.depositTo{value: 100 ether}(address(bobAcct));

        // Add money to the paymaster
        flopsPaymaster.deposit{value: 100 ether}();
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

    // Magic placeholder is added so that the getUserOpHash is identical once the paymaster signature is appended
    function staticPaymasterFieldsWithMagicPlaceholder(
        address paymaster,
        uint128 verificationGasLimit,
        uint128 postOpGasLimit
    ) public pure returns (bytes memory) {
        return abi.encodePacked(paymaster, verificationGasLimit, postOpGasLimit, UserOperationLib.PAYMASTER_SIG_MAGIC);
    }

    function buildPaymasterAndData(
        address paymaster,
        uint128 verificationGasLimit,
        uint128 postOpGasLimit,
        FlopsData memory flopsData,
        uint256 privateKey
    ) public returns (bytes memory) {
        // Sign over the flopsData
        bytes32 commitmentHash = flopsPaymaster.computeBundlerCommitHash(flopsData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, commitmentHash);
        bytes memory signature = abi.encodePacked(r, s, v);

        // Build the FlopsCommitment
        FlopsCommitment memory flopsCommitment = FlopsCommitment({data: flopsData, signature: signature});

        // Encode the FlopsCommitment with PAYMASTER_SIG_MAGIC
        bytes memory paymasterSignature = abi.encode(flopsCommitment);
        bytes memory paymasterSignatureWithLength = userOperationLibHelper.encodePaymasterSignature(paymasterSignature);

        return abi.encodePacked(paymaster, verificationGasLimit, postOpGasLimit, paymasterSignatureWithLength);
    }
}
