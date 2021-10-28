// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

contract CloakService {
    address public teeAddr;
    mapping(address => string) pks;
    mapping(address => bool) hasAnnounced;
    // TODO: add tee proof
    function setTEEAddress(string memory pk) public {
        require(teeAddr == address(0), "TEE has already register");
        teeAddr = msg.sender;
        pks[msg.sender] = pk;
    }

    function getTEEAddress() public view returns (address) {
        return teeAddr;
    }
    
    function announcePk(string calldata pk) external {
        require(hasAnnounced[msg.sender], "Address has no announced");
        pks[msg.sender] = pk;
        hasAnnounced[msg.sender] = true;
    }

    function getPk(address[] memory addrs) public view returns(string[] memory) {
        string[] memory res = new string[](addrs.length);
        for (uint i = 0; i < addrs.length; i++) {
            require(hasAnnounced[addrs[i]], "Address has no announced");
            res[i] = pks[addrs[i]];
        }
        return res;
    }
}
