/// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;


library ECRecover {
    /**
     * @notice Recover signer's address from a signed message
     * @dev Adapted from: https://github.com/OpenZeppelin/openzeppelin-contracts/blob/65e4ffde586ec89af3b7e9140bdc9235d1254853/contracts/cryptography/ECDSA.sol
     * Modifications: Accept v, r, and s as separate arguments
     * @param digest    Keccak-256 hash digest of the signed message
     * @param v         v of the signature
     * @param r         r of the signature
     * @param s         s of the signature
     * @return Signer address
     */
    function recover(
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal pure returns (address) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        // if (
        //     uint256(s) >
        //     0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        // ) {
        //     revert("ECRecover: invalid signature 's' value");
        // }
        if( uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) revert InvalidSignature();

        // if (v != 27 && v != 28) {
        //     revert("ECRecover: invalid signature 'v' value");
        // }
        if(v != 27 && v != 28) revert InvalidSignature();

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(digest, v, r, s);
        // require(signer != address(0), "ECRecover: invalid signature");
        if(signer == address(0)) revert CannotBeZeroAddress();

        return signer;
    }
}


library EIP712 {
    /**
     * @notice Make EIP712 domain separator
     * @param name      Contract name
     * @param version   Contract version
     * @return Domain separator
     */
    function makeDomainSeparator(string memory name, string memory version)
        internal
        view
        returns (bytes32)
    {
        uint256 chainId;
        assembly {
            chainId := chainid()
        }
        return
            keccak256(
                abi.encode(
                    // keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")
                    0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f,
                    keccak256(bytes(name)),
                    keccak256(bytes(version)),
                    chainId,
                    address(this)
                )
            );
    }

    /**
     * @notice Recover signer's address from a EIP712 signature
     * @param domainSeparator   Domain separator
     * @param v                 v of the signature
     * @param r                 r of the signature
     * @param s                 s of the signature
     * @param typeHashAndData   Type hash concatenated with data
     * @return Signer's address
     */
    function recover(
        bytes32 domainSeparator,
        uint8 v,
        bytes32 r,
        bytes32 s,
        bytes memory typeHashAndData
    ) internal pure returns (address) {
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator,
                keccak256(typeHashAndData)
            )
        );
        return ECRecover.recover(digest, v, r, s);
    }
}

//import { AbstractFiatTokenV1 } from "../v1/AbstractFiatTokenV1.sol";
//import { IERC20 } from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "../Staking/ILockReceiver.sol";
abstract contract AbstractFiatTokenV1 {//is IERC20 {
    function _approve(
        address owner,
        address spender,
        uint256 value
    ) internal virtual;

    function _transfer(
        address from,
        address to,
        uint256 value
    ) internal virtual;
}


abstract contract AbstractFiatTokenV2 is AbstractFiatTokenV1 {
    function _increaseAllowance(
        address owner,
        address spender,
        uint256 increment
    ) internal virtual;

    function _decreaseAllowance(
        address owner,
        address spender,
        uint256 decrement
    ) internal virtual;
}

contract EIP712Domain {
    /**
     * @dev EIP712 Domain Separator
     */
    bytes32 public DOMAIN_SEPARATOR;
}


// import { AbstractFiatTokenV2 } from "./AbstractFiatTokenV2.sol";
// import { EIP712Domain } from "./EIP712Domain.sol";
// import { EIP712 } from "../util/EIP712.sol";
abstract contract EIP2612 is AbstractFiatTokenV2, EIP712Domain {
    // keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)")
    bytes32
        public constant PERMIT_TYPEHASH = 0x6e71edae12b1b97f4d1f60370fef10105fa2faae0126114a169c64845d6126c9;

    mapping(address => uint256) private _permitNonces;

    /**
     * @notice Nonces for permit
     * @param owner Token owner's address (Authorizer)
     * @return Next nonce
     */
    function nonces(address owner) external view returns (uint256) {
        return _permitNonces[owner];
    }

    /**
     * @notice Verify a signed approval permit and execute if valid
     * @param owner     Token owner's address (Authorizer)
     * @param spender   Spender's address
     * @param value     Amount of allowance
     * @param deadline  The time at which this expires (unix time)
     * @param v         v of the signature
     * @param r         r of the signature
     * @param s         s of the signature
     */
    function _permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        // require(deadline >= block.timestamp, "FiatTokenV2: permit is expired");
        if(deadline < block.timestamp) revert InvalidDeadline();

        bytes memory data = abi.encode(
            PERMIT_TYPEHASH,
            owner,
            spender,
            value,
            _permitNonces[owner]++,
            deadline
        );
        // require(
        //     EIP712.recover(DOMAIN_SEPARATOR, v, r, s, data) == owner,
        //     "EIP2612: invalid signature"
        // );
        if(EIP712.recover(DOMAIN_SEPARATOR, v, r, s, data) != owner) revert InvalidSignature();

        _approve(owner, spender, value);
    }
}

error  InvalidTimestamp();
error  InvalidSignature();
//error  InvalidNonce();
error  InvalidDeadline();
error AuthorizationUsedOrCanceled();
error CannotBeZeroAddress();
/**
 * @title EIP-3009
 * @notice Provide internal implementation for gas-abstracted transfers
 * @dev Contracts that inherit from this must wrap these with publicly
 * accessible functions, optionally adding modifiers where necessary
 */
abstract contract EIP3009 is AbstractFiatTokenV2, EIP712Domain {
    // keccak256("TransferWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    bytes32
        public constant TRANSFER_WITH_AUTHORIZATION_TYPEHASH = 0x7c7c6cdb67a18743f49ec6fa9b35f50d52ed05cbed4cc592e13b44501c1a2267;

    // keccak256("ReceiveWithAuthorization(address from,address to,uint256 value,uint256 validAfter,uint256 validBefore,bytes32 nonce)")
    // bytes32
    //     public constant RECEIVE_WITH_AUTHORIZATION_TYPEHASH = 0xd099cc98ef71107a616c4f0f941f04c322d8e254fe26b3c6668db87aae413de8;

    // keccak256("CancelAuthorization(address authorizer,bytes32 nonce)")
    bytes32
        public constant CANCEL_AUTHORIZATION_TYPEHASH = 0x158b0a9edf7a828aad02f63cd515c68ef2f50ba807396f6d12842833a1597429;

    /**
     * @dev authorizer address => nonce => bool (true if nonce is used)
     */
    mapping(address => mapping(bytes32 => bool)) private _authorizationStates;

    event AuthorizationUsed(address indexed authorizer, bytes32 indexed nonce);
    event AuthorizationCanceled(
        address indexed authorizer,
        bytes32 indexed nonce
    );

    /**
     * @notice Returns the state of an authorization
     * @dev Nonces are randomly generated 32-byte data unique to the
     * authorizer's address
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @return True if the nonce is used
     */
    function authorizationState(address authorizer, bytes32 nonce)
        external
        view
        returns (bool)
    {
        return _authorizationStates[authorizer][nonce];
    }

    // /**
    //  * @notice Execute a transfer with a signed authorization
    //  * @param from          Payer's address (Authorizer)
    //  * @param to            Payee's address
    //  * @param value         Amount to be transferred
    //  * @param validAfter    The time after which this is valid (unix time)
    //  * @param validBefore   The time before which this is valid (unix time)
    //  * @param nonce         Unique nonce
    //  * @param v             v of the signature
    //  * @param r             r of the signature
    //  * @param s             s of the signature
    //  */
    // function _transferWithAuthorization(
    //     address from,
    //     address to,
    //     uint256 value,
    //     uint256 validAfter,
    //     uint256 validBefore,
    //     bytes32 nonce,
    //     uint8 v,
    //     bytes32 r,
    //     bytes32 s
    // ) internal {
    //     // _requireValidAuthorization(from, nonce, validAfter, validBefore);

    //     bytes memory data = abi.encode(
    //         TRANSFER_WITH_AUTHORIZATION_TYPEHASH,
    //         from,
    //         to,
    //         value,
    //         validAfter,
    //         validBefore,
    //         nonce
    //     );
    //     // require(
    //     //     EIP712.recover(DOMAIN_SEPARATOR, v, r, s, data) == from,
    //     //     "FiatTokenV2: invalid signature"
    //     // );
    //     if(EIP712.recover(DOMAIN_SEPARATOR, v, r, s, data) != from) revert InvalidSignature();
        
    //     _markAuthorizationAsUsed(from, nonce);
    //     _transfer(from, to, value);
    // }

    // /**
    //  * @notice Receive a transfer with a signed authorization from the payer
    //  * @dev This has an additional check to ensure that the payee's address
    //  * matches the caller of this function to prevent front-running attacks.
    //  * @param from          Payer's address (Authorizer)
    //  * @param to            Payee's address
    //  * @param value         Amount to be transferred
    //  * @param validAfter    The time after which this is valid (unix time)
    //  * @param validBefore   The time before which this is valid (unix time)
    //  * @param nonce         Unique nonce
    //  * @param v             v of the signature
    //  * @param r             r of the signature
    //  * @param s             s of the signature
    //  */
    // function _receiveWithAuthorization(
    //     address from,
    //     address to,
    //     uint256 value,
    //     uint256 validAfter,
    //     uint256 validBefore,
    //     bytes32 nonce,
    //     uint8 v,
    //     bytes32 r,
    //     bytes32 s
    // ) internal {
    //     // require(to == msg.sender, "FiatTokenV2: caller must be the payee");
    //     if(to != msg.sender) revert InvalidSignature();
    //     _requireValidAuthorization(from, nonce, validAfter, validBefore);

    //     bytes memory data = abi.encode(
    //         RECEIVE_WITH_AUTHORIZATION_TYPEHASH,
    //         from,
    //         to,
    //         value,
    //         validAfter,
    //         validBefore,
    //         nonce
    //     );
    //     // require(
    //     //     EIP712.recover(DOMAIN_SEPARATOR, v, r, s, data) == from,
    //     //     "FiatTokenV2: invalid signature"
    //     // );
    //     if(EIP712.recover(DOMAIN_SEPARATOR, v, r, s, data) != from) revert InvalidSignature();
    //     _markAuthorizationAsUsed(from, nonce);
    //     _transfer(from, to, value);
    // }

    /**
     * @notice Attempt to cancel an authorization
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @param v             v of the signature
     * @param r             r of the signature
     * @param s             s of the signature
     */
    function _cancelAuthorization(
        address authorizer,
        bytes32 nonce,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal {
        _requireUnusedAuthorization(authorizer, nonce);

        bytes memory data = abi.encode(
            CANCEL_AUTHORIZATION_TYPEHASH,
            authorizer,
            nonce
        );
        // require(
        //     EIP712.recover(DOMAIN_SEPARATOR, v, r, s, data) == authorizer,
        //     "FiatTokenV2: invalid signature"
        // );
        if(EIP712.recover(DOMAIN_SEPARATOR, v, r, s, data) != authorizer) revert InvalidSignature();

        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationCanceled(authorizer, nonce);
    }

    /**
     * @notice Check that an authorization is unused
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     */
    function _requireUnusedAuthorization(address authorizer, bytes32 nonce)
        private
        view
    {
        // require(
        //     !_authorizationStates[authorizer][nonce],
        //     "FiatTokenV2: authorization is used or canceled"
        // );
        if(_authorizationStates[authorizer][nonce]) revert AuthorizationUsedOrCanceled();
    }

    /**
     * @notice Check that authorization is valid
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     * @param validAfter    The time after which this is valid (unix time)
     * @param validBefore   The time before which this is valid (unix time)
     */
    function _requireValidAuthorization(
        address authorizer,
        bytes32 nonce,
        uint256 validAfter,
        uint256 validBefore
    ) private view {
        // require(
        //     block.timestamp > validAfter,
        //     "FiatTokenV2: authorization is not yet valid"
        // );
        // require(block.timestamp < validBefore, "FiatTokenV2: authorization is expired");
        if(block.timestamp <= validAfter) revert InvalidTimestamp();
        if(block.timestamp >= validBefore) revert InvalidTimestamp();

        _requireUnusedAuthorization(authorizer, nonce);
    }

    /**
     * @notice Mark an authorization as used
     * @param authorizer    Authorizer's address
     * @param nonce         Nonce of the authorization
     */
    function _markAuthorizationAsUsed(address authorizer, bytes32 nonce)
        private
    {
        _authorizationStates[authorizer][nonce] = true;
        emit AuthorizationUsed(authorizer, nonce);
    }
}
