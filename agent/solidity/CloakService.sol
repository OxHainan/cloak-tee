// SPDX-License-Identifier: Apache-2.0

pragma solidity ^0.8.0;

contract CloakService {
    address public teeAddr;

    // TODO: add tee proof
    function setTEEAddress() public {
        teeAddr = msg.sender;
    }

    function getTEEAddress() public view returns (address) {
        return teeAddr;
    }
}
