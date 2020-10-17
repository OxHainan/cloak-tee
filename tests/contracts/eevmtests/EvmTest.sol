pragma solidity ^0.5.1;

library Math {
    function add(uint256 a, uint256 b) public pure returns (uint256) {
        return a + b;
    }
}

contract EvmTest {
    using Math for *;

    uint256 owneraddr;
    uint256 test;

    /// Create a new ballot with $(_numProposals) different proposals.
    constructor(uint256 _addr, uint256[] memory _numProposals) public {
        owneraddr = _addr;
        test = _numProposals[0];
    }

    function getSum(uint256 _a, uint256 _b) public pure returns (uint256) {
        return Math.add(_a, _b);
    }
}
