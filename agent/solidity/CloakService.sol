// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

contract CloakService {
    address public teeAddr;
    mapping(address => bytes) public pks;
    mapping(address => bool) hasAnnounced;

    modifier check_public_key(bytes memory pk) {
        require(pk.length == 65, "Invalid public key length");
        require(pk[0] == 0x04, "Unkown public key format");
        _;
    }

    // TODO: add tee proof
    function setTEEAddress(bytes memory pk) public {
        require(teeAddr == address(0), "TEE has already register");
        teeAddr = msg.sender;
        announcePk(pk);
    }

    function getTEEAddress() public view returns (address) {
        return teeAddr;
    }
    
    function announcePk(bytes memory pk) check_public_key(pk) public {
        require(!hasAnnounced[msg.sender], "Address has already announced");
        pks[msg.sender] = pk;
        hasAnnounced[msg.sender] = true;
    }

    function getPk(address[] memory addrs) public view returns(bytes[] memory) {
        bytes[] memory res = new bytes[](addrs.length);
        for (uint i = 0; i < addrs.length; i++) {
            require(hasAnnounced[addrs[i]], "Address has no announced");
            res[i] = pks[addrs[i]];
        }
        return res;
    }
}
