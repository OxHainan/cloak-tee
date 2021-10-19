// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

contract CloakPKI {
    mapping(address => string) pks;
    mapping(address => bool) hasAnnounced;

    function announcePk(string calldata pk) external {
        pks[msg.sender] = pk;
        hasAnnounced[msg.sender] = true;
    }

    function getPk(address[] memory addrs) public view returns(string[] memory) {
        string[] memory res = new string[](addrs.length);
        for (uint i = 0; i < addrs.length; i++) {
            require(hasAnnounced[addrs[i]], string(abi.encode(addrs[i])));
            res[i] = pks[addrs[i]];
        }
        return res;
    }
}
