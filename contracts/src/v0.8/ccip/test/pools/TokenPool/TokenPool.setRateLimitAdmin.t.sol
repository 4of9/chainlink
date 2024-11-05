// SPDX-License-Identifier: BUSL-1.1
pragma solidity 0.8.24;

import {Ownable2Step} from "../../../../shared/access/Ownable2Step.sol";
import {TokenPoolSetup} from "./TokenPoolSetup.t.sol";

contract TokenPool_setRateLimitAdmin is TokenPoolSetup {
  function test_SetRateLimitAdmin_Success() public {
    assertEq(address(0), s_tokenPool.getRateLimitAdmin());
    s_tokenPool.setRateLimitAdmin(OWNER);
    assertEq(OWNER, s_tokenPool.getRateLimitAdmin());
  }

  // Reverts

  function test_SetRateLimitAdmin_Revert() public {
    vm.startPrank(STRANGER);

    vm.expectRevert(Ownable2Step.OnlyCallableByOwner.selector);
    s_tokenPool.setRateLimitAdmin(STRANGER);
  }
}