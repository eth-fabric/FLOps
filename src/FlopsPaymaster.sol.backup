// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {PackedUserOperation} from "lib/account-abstraction/contracts/interfaces/PackedUserOperation.sol";
import {BasePaymaster} from "lib/account-abstraction/contracts/core/BasePaymaster.sol";
import {IEntryPoint} from "lib/account-abstraction/contracts/interfaces/IEntryPoint.sol";
import {UserOperationLib} from "lib/account-abstraction/contracts/core/UserOperationLib.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";

import {IFlopsPaymaster} from "./IFlopsPaymaster.sol";
import {IFlopsAccountFactory} from "./IFlopsAccountFactory.sol";
import {BlockState, FlopsData, FlopsCommitment} from "./FlopsStructs.sol";

contract FlopsPaymaster is BasePaymaster, IFlopsPaymaster {
    event BlockBroken(uint64 indexed blockNumber, bytes32 userOpHash);

    mapping(address => bool) public approvedBundlers;
    mapping(uint64 => BlockState) public blocks;
    IFlopsAccountFactory private _factory;

    constructor(IEntryPoint _entryPoint, address _owner, address[] memory bundlers) BasePaymaster(_entryPoint, _owner) {
        for (uint256 i = 0; i < bundlers.length; i++) {
            approvedBundlers[bundlers[i]] = true;
        }
    }

    /**
     * Validate a user operation.
     * @param userOp     - The user operation.
     * @param userOpHash - The hash of the user operation.
     * @param maxCost    - The maximum cost of the user operation.
     */
    function _validatePaymasterUserOp(PackedUserOperation calldata userOp, bytes32 userOpHash, uint256 maxCost)
        internal
        override
        returns (bytes memory context, uint256 validationData)
    {
        uint64 blockNumber = uint64(block.number);
        FlopsData memory d =
        abi.decode(UserOperationLib.getPaymasterSignature(userOp.paymasterAndData), (FlopsCommitment)).data;

        // FLOps guardrail: FLOps must execute in the block it was committed for
        if (d.blockNumber != blockNumber) {
            blocks[blockNumber].broken = true;
            emit BlockBroken(blockNumber, d.userOpHash);
            return ("", 0);
        }

        bool broken = false;

        // Verify pre-transaction state
        if (d.preTxState != blocks[blockNumber].rollingHash) broken = true;

        // Verify bundler signature
        if (!verifyBundlerSignature(userOp)) broken = true;

        // Verify bundle only contains FlopsAccount transactions
        if (!_factory.isFlopsAccount(userOp.sender)) broken = true;

        if (broken) {
            // FLOps violation detected during validation
            blocks[blockNumber].broken = true;
            emit BlockBroken(blockNumber, d.userOpHash);
            return ("", 0);
        }

        // Happy path: advance rolling hash for this block
        blocks[blockNumber].rollingHash = keccak256(abi.encode(blocks[blockNumber].rollingHash, d.userOpHash));

        return ("", 0);
    }

    /**
     * Post-operation handler.
     * (verified to be called only through the entryPoint)
     * @dev If subclass returns a non-empty context from validatePaymasterUserOp,
     *      it must also implement this method.
     * @param mode          - Enum with the following options:
     *                        opSucceeded - User operation succeeded.
     *                        opReverted  - User op reverted. The paymaster still has to pay for gas.
     *                        postOpReverted - never passed in a call to postOp().
     * @param context       - The context value returned by validatePaymasterUserOp
     * @param actualGasCost - Actual cost of gas used so far (without this postOp call).
     * @param actualUserOpFeePerGas - the gas price this UserOp pays. This value is based on the UserOp's maxFeePerGas
     *                        and maxPriorityFee (and basefee)
     *                        It is not the same as tx.gasprice, which is what the bundler pays.
     */
    function _postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 actualUserOpFeePerGas)
        internal
        override
    {
        // FLOps guardrail: if the transaction reverted, mark the block as broken
        // This is for guaranteeing correct execution
        if (mode != PostOpMode.opSucceeded) {
            blocks[uint64(block.number)].broken = true;
            emit BlockBroken(uint64(block.number), bytes32(0)); // todo: add userOpHash via context
        }
        // any billing or accounting can go here later
    }

    function nextRollingHash(PackedUserOperation calldata userOp) public view returns (bytes32) {
        return keccak256(abi.encode(blocks[uint64(block.number)].rollingHash, entryPoint().getUserOpHash(userOp)));
    }

    function verifyBundlerSignature(PackedUserOperation calldata userOp) public view returns (bool) {
        // Retrieve the FlopsCommitment from the paymasterAndData
        bytes calldata flopsBytes = UserOperationLib.getPaymasterSignature(userOp.paymasterAndData);
        FlopsCommitment memory commitment = abi.decode(flopsBytes, (FlopsCommitment));

        // Verify the committed userOpHash matches the computed userOpHash
        if (commitment.data.userOpHash != entryPoint().getUserOpHash(userOp)) return false;

        // Compute the commitment hash
        bytes32 commitmentHash = computeBundlerCommitHash(commitment.data);

        // Verify the signer is an approved bundler
        address recovered = ECDSA.recover(commitmentHash, commitment.signature);
        return approvedBundlers[recovered];
    }

    function blockBroken() external view returns (bool) {
        return blocks[uint64(block.number)].broken;
    }

    function blockBroken(uint64 blockNumber) external view returns (bool) {
        return blocks[blockNumber].broken;
    }

    function setFactory(address factory_) external onlyOwner {
        _factory = IFlopsAccountFactory(factory_);
    }

    function factory() external view returns (address) {
        return address(_factory);
    }

    function computeBundlerCommitHash(FlopsData memory data) public view returns (bytes32) {
        bytes32 digest = keccak256(abi.encode(data));
        return MessageHashUtils.toEthSignedMessageHash(digest);
    }
}
