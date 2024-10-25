# The Standard - Findings Report

# Table of contents
- ## [Contest Summary](#contest-summary)
- ## [Results Summary](#results-summary)
- ## High Risk Findings
    - ### [H-01. Missing access control  in `distributeAssets` function](#H-01)
- ## Medium Risk Findings
    - ### [M-01. Not burning enough `EUROs` at liquidation of smartVault](#M-01)
    - ### [M-02. User can't withdraw max collateral if have `minted euro`](#M-02)
    - ### [M-03. Using `block.timestamp` as deadline in swap](#M-03)
- ## Low Risk Findings
    - ### [L-01. Disallowing accepted token will lead stakers to loss fund](#L-01)


# <a id='contest-summary'></a>Contest Summary

### Sponsor: The Standard

### Dates: Dec 27th, 2023 - Jan 10th, 2024

[See more contest details here](https://codehawks.cyfrin.io/c/clql6lvyu0001mnje1xpqcuvl)

# <a id='results-summary'></a>Results Summary

### Number of findings:
- High: 1
- Medium: 3
- Low: 1


# High Risk Findings

## <a id='H-01'></a>H-01. Missing access control  in `distributeAssets` function            

### Relevant GitHub Links

https://github.com/Cyfrin/2023-12-the-standard/blob/91132936cb09ef9bf82f38ab1106346e2ad60f91/contracts/LiquidationPool.sol#L205

## Summary
`LiquidationPool::distributeAssets`  can be called by any malicious user because of missing access control which will cause LiquidationPool to loss funds

## Vulnerability Details
A user is liquidated through `runLiquidation` function in LiquidationPoolManager, which calculates which token user was holding along with amount, and calls the `distributeAssets` function in LiquidationPool with `assets`, `collateralRate`, `HUNDRED_PC` as parameters, but `distributeAssets` is missing access control that `onlyManager` should call this function
```solidity
 function runLiquidation(uint256 _tokenId) external {
        // code......
 @>       LiquidationPool(pool).distributeAssets{value: ethBalance}(assets, manager.collateralRate(), manager.HUNDRED_PC());
        forwardRemainingRewards(tokens);
    }
```
Here we can see `distributeAssets` has no access control
```solidity
  function distributeAssets(ILiquidationPoolManager.Asset[] memory _assets, uint256 _collateralRate, uint256 _hundredPC) external payable {
             // code.......
    }
```
How this will work (POC)
1. User will call this `distributeAssets` with malicious parameters
2. distributeAssets is calculating `_portion` based on `_assets.amount`, this will be inflated to get more portion
```solidity
uint256 _portion = (asset.amount * _positionStake) / stakeTotal;
```
3. `costInEuros` of that portion can be reduced because it is calculated based on `_collateralRate` & `_hundredPC`
```solidity
  uint256 costInEuros = _portion * 10 ** (18 - asset.token.dec) * uint256(assetPriceUsd) / uint256(priceEurUsd)
                            * _hundredPC / _collateralRate;
```
4. EURO from position will be reduced and `reward` will be set
5. Now, functions is  transferring token from manager to LiquidationPool address, this will revert if manager has not enough tokens but there is no check for ETH which means if we pass only ETH in `_asset` parameter then it will work because its only increasing `nativePurchased`( ie will set reward and will take less euro for that )
```solidity
  if (asset.token.addr == address(0)) {
           nativePurchased += _portion;
       } else {
            IERC20(asset.token.addr).safeTransferFrom(manager, address(this), _portion);
      }
```

## Impact
Liquidation pool will loss funds as wrong rewards has been set by malicious user

## Tools Used
Manual Review

## Recommendations
Use `onlyManager` access control in `distributeAssets` like we've done in `distributeFees`
    
# Medium Risk Findings

## <a id='M-01'></a>M-01. Not burning enough `EUROs` at liquidation of smartVault            

### Relevant GitHub Links

https://github.com/Cyfrin/2023-12-the-standard/blob/91132936cb09ef9bf82f38ab1106346e2ad60f91/contracts/LiquidationPool.sol#L239

https://github.com/Cyfrin/2023-12-the-standard/blob/91132936cb09ef9bf82f38ab1106346e2ad60f91/contracts/SmartVaultV3.sol#L117

## Summary
`runLiquidation` is not burning enough `EUROs` at liquidation of `SmartVault` which will lead to undercollateralization

## Vulnerability Details
When there is `liquidation` of a vault, we are setting `minted = 0` then we should burn the amount of `EUROs` that vault had minted inorder to keep the protocol overcollateralized . We are taking % of EUROs from all the stakers to cover that minted EUROs, but that is not equal to the amount of minted EUROs in liquidated vault
```solidity
  function liquidate() external onlyVaultManager {
        require(undercollateralised(), "err-not-liquidatable");
        liquidated = true;
@>        minted = 0;
        liquidateNative();
        ITokenManager.Token[] memory tokens = getTokenManager().getAcceptedTokens();
        for (uint256 i = 0; i < tokens.length; i++) {
            if (tokens[i].symbol != NATIVE) liquidateERC20(IERC20(tokens[i].addr));
        }
    }
```
```solidity
        function distributeAssets(ILiquidationPoolManager.Asset[] memory _assets, uint256 _collateralRate, uint256 _hundredPC) external payable {
        consolidatePendingStakes();
                    //
                    // code......
                   //
                        (,int256 assetPriceUsd,,,) = Chainlink.AggregatorV3Interface(asset.token.clAddr).latestRoundData();
                        uint256 _portion = asset.amount * _positionStake / stakeTotal;
                        uint256 costInEuros = _portion * 10 ** (18 - asset.token.dec) * uint256(assetPriceUsd) / uint256(priceEurUsd)
                            * _hundredPC / _collateralRate;
                        if (costInEuros > _position.EUROs) {
                            _portion = _portion * _position.EUROs / costInEuros;
                            costInEuros = _position.EUROs;
                        }
                        _position.EUROs -= costInEuros;
                        rewards[abi.encodePacked(_position.holder, asset.token.symbol)] += _portion;
                        burnEuros += costInEuros;
                        if (asset.token.addr == address(0)) {
                            nativePurchased += _portion;
                        } else {
                            IERC20(asset.token.addr).safeTransferFrom(manager, address(this), _portion);
                        }
                    }
                }
            }
            positions[holders[j]] = _position;
        }
  @>   if (burnEuros > 0) IEUROs(EUROs).burn(address(this), burnEuros);
        returnUnpurchasedNative(_assets, nativePurchased);
    }
```
Here is how this will work(POC)
1. User deposited 1 eth at 1000 usd price
2. maxMintable will be 833.3 euro at 120% collateralRate and at 1.0 conversion rate from usd to euro(for simplicity)
3. User max minted his euros ie 833.3
4. Price of eth dropped by 10% to 900 usd and vault became undercollateralized 
Above 4 points can be anything but the core is vault should be undercolleralized
5. Now, there are 2 staker in LiquidityPool, S1 has 1000 TST & 2000 EUROs while S2 has 4000 TST & 3000 EUROs
6. `portion` that S1 will get is 1/4 ie 25% of 1 eth, similarly S2 will get 3/4 of 1 eth
```solidity
 uint256 _portion = asset.amount * _positionStake / stakeTotal;
```
7. `costInEuro` for that portion of S1 will be 187.5 euro while for S2 will be 562.5 euro
```solidity
 uint256 costInEuros = _portion * 10 ** (18 - asset.token.dec) * uint256(assetPriceUsd) / uint256(priceEurUsd)
                            * _hundredPC / _collateralRate;
```
8. total euro that stakers are giving is 187.5 + 562.5 = 750 euros, but vault have minted 833.3 euro which is ~10% less
```solidity
 if (burnEuros > 0) IEUROs(EUROs).burn(address(this), burnEuros);
```
Every time a vault will be liquidated, this will happen

## Impact
We'll have more EUROs minted than backing it, system will eventually become overcollateralized 

## Tools Used
Manual Review

## Recommendations
One thing that can be done is to reduce discount that stakers are receiving or protocol can pay the extra euros
## <a id='M-02'></a>M-02. User can't withdraw max collateral if have `minted euro`            

### Relevant GitHub Links

https://github.com/Cyfrin/2023-12-the-standard/blob/91132936cb09ef9bf82f38ab1106346e2ad60f91/contracts/SmartVaultV3.sol#L127

## Summary
User can't withdraw max collateral from vault if have any minted euros because wrong calculations in `canRemoveCollateral` function

## Vulnerability Details
A user should withdraw all the collateral, except enough collateral require to back the minted euros, but with current implementation its not possible because `canRemoveCollateral` function is using `maxMintable` in calculation instead of `euroCollateral`
```solidity
  function canRemoveCollateral(ITokenManager.Token memory _token, uint256 _amount) private view returns (bool) {
        if (minted == 0) return true;
   @>     uint256 currentMintable = maxMintable();
        uint256 eurValueToRemove = calculator.tokenToEurAvg(_token, _amount);
        return currentMintable >= eurValueToRemove &&
            minted <= currentMintable - eurValueToRemove;
    }
```

How this will work:-
1. User deposited 6000 euro worth of collateral in the vault
2. maxMintable at 120% collateral rate will be 5000 euro ie:- ((6000 * 100000)/120000) = 5000
```solidity
 function maxMintable() private view returns (uint256) {
        return euroCollateral() * ISmartVaultManagerV3(manager).HUNDRED_PC() / ISmartVaultManagerV3(manager).collateralRate();
    }
```
3. User minted 2000 euros
4. Total collateral required to back 2000 minted euros is 2400 euro worth collateral ie:- ( mintedEuros * collateralRate)/ HUNDRED_PC, `(2000 * 120000)/100000`
5. Available collateral to withdraw is 6000 - 2400 = 3600 euro worth collateral, but with current implementation user can only withdraw 3000 worth of collateral, which is 600 euro less worth of collateral
6. This 600 can go up depending upon the size of collateral and minted euros

Here is the POC( run this test in smartVault.js test file )
```javascript
 it("user can not withdraw max collateral", async () => {
      // depositing tether as collateral
      const Tether = await (
        await ethers.getContractFactory("ERC20Mock")
      ).deploy("Tether", "USDT", 6);
      const USDTBytes = ethers.utils.formatBytes32String("USDT");
      const clUsdUsdPrice = 100000000; //$1
      const ClUsdUsd = await (
        await ethers.getContractFactory("ChainlinkMock")
      ).deploy("USD / USD");
      await ClUsdUsd.setPrice(clUsdUsdPrice);
      await TokenManager.addAcceptedToken(Tether.address, ClUsdUsd.address);

      // 6360 USDT will worth 6000 euro at 1.06 conversion rate
      const value = 6360000000;
      await Tether.mint(Vault.address, value);

      // minting 1990 euro which will make minted = 2000 euro after adding mintFee
      const mintvalue = ethers.utils.parseEther("1990");
      await Vault.connect(user).mint(user.address, mintvalue);

      let { minted, maxMintable, totalCollateralValue } = await Vault.status();
      console.log(totalCollateralValue);
      console.log(maxMintable);
      console.log(minted);

      // 3816 USDT will worth 3600 euro at 1.06 conversion rate
      // 3180 USDT will worth 3000 euro, anything below this will be removed as collateral
      const removeValue = 3816000000;
      let removeCollateral = Vault.connect(user).removeCollateral(
        USDTBytes,
        removeValue,
        user.address
      );
      await expect(removeCollateral).to.be.revertedWith("err-under-coll");
    });
```

## Impact
No loss of funds but will grief user

## Tools Used
Manual Review

## Recommendations
Use `euroCollateral` instead of `maxMintable` in calculation
```diff
  function canRemoveCollateral(ITokenManager.Token memory _token, uint256 _amount) private view returns (bool) {
        if (minted == 0) return true;
-        uint256 currentMintable = maxMintable();
        uint256 eurValueToRemove = calculator.tokenToEurAvg(_token, _amount);
-        return currentMintable >= eurValueToRemove &&
-            minted <= currentMintable - eurValueToRemove;
    }
```
```diff
 function canRemoveCollateral(ITokenManager.Token memory _token, uint256 _amount) private view returns (bool) {
        if (minted == 0) return true;
+        uint256 currentEuroCollateral = euroCollateral();
        uint256 eurValueToRemove = calculator.tokenToEurAvg(_token, _amount);
+        uint256 requiredCollateralValue =
+            minted * ISmartVaultManagerV3(manager).collateralRate() / ISmartVaultManagerV3(manager).HUNDRED_PC();
+        return currentEuroCollateral >= eurValueToRemove
+            && requiredCollateralValue <= currentEuroCollateral - eurValueToRemove;
    }
## <a id='M-03'></a>M-03. Using `block.timestamp` as deadline in swap            

### Relevant GitHub Links

https://github.com/Cyfrin/2023-12-the-standard/blob/91132936cb09ef9bf82f38ab1106346e2ad60f91/contracts/SmartVaultV3.sol#L223C19-L223C19

## Summary
Using block.timestamp as deadline in swap could lead to users getting worse price than expected

## Vulnerability Details
In `SmartVault::swap`, we are using block.timestamp as deadline which means transaction will stay in the mempool for an extensive period of time without reverting which could lead to users getting worse price than expected
```solidity
 function swap(bytes32 _inToken, bytes32 _outToken, uint256 _amount) external onlyOwner {
        uint256 swapFee = _amount * ISmartVaultManagerV3(manager).swapFeeRate() / ISmartVaultManagerV3(manager).HUNDRED_PC();
        address inToken = getSwapAddressFor(_inToken);
        uint256 minimumAmountOut = calculateMinimumAmountOut(_inToken, _outToken, _amount);
        ISwapRouter.ExactInputSingleParams memory params = ISwapRouter.ExactInputSingleParams({
                tokenIn: inToken,
                tokenOut: getSwapAddressFor(_outToken),
                fee: 3000,
                recipient: address(this),
         @>       deadline: block.timestamp,
                amountIn: _amount - swapFee,
                amountOutMinimum: minimumAmountOut,
                sqrtPriceLimitX96: 0
            });
        inToken == ISmartVaultManagerV3(manager).weth() ?
            executeNativeSwapAndFee(params, swapFee) :
            executeERC20SwapAndFee(params, swapFee);
    }
```

## Impact
Users can get worse price

## Tools Used
Manual review

## Recommendations
Use bounded deadline for swaps

# Low Risk Findings

## <a id='L-01'></a>L-01. Disallowing accepted token will lead stakers to loss fund            

### Relevant GitHub Links

https://github.com/Cyfrin/2023-12-the-standard/blob/91132936cb09ef9bf82f38ab1106346e2ad60f91/contracts/SmartVaultV3.sol#L149

## Summary
When a `accepted token` is removed/disallowed then immediately it undercollateralized many smart vaults using that token, also it leads stakers to loss funds
## Vulnerability Details
User can `deposit` any token to smart vaults, if it's accepted token then user can `mint` against it, if it's not then can `remove` token using `removeAsset` function. But if a `accepted token` is removed/disallowed then vaults using that token will became undercollateralized and when vault gets liquidated then that token will not go to pool as it's not a accepted token now, and user will also be able to remove that token using `removeAsset` function

How this works:-
1. User `deposited` 1000 USDT(for example)
2. Minted 500 euros against it
3. Owner removed USDT as collateral
4. Vault got undercollateralized and gets liquidated
5. Now, user can use `removeAsset` function to withdraw that deposited USDT

//Here is the POC 
```solidity
it("Disallowing token leads loss of funds", async () => {
      // Using Tether as a collateral for testing
      const Tether = await (
        await ethers.getContractFactory("ERC20Mock")
      ).deploy("Tether", "USDT", 6);
      const USDTBytes = ethers.utils.formatBytes32String("USDT");
      const clUsdUsdPrice = 100000000;
      const ClUsdUsd = await (
        await ethers.getContractFactory("ChainlinkMock")
      ).deploy("USD / USD");
      await ClUsdUsd.setPrice(clUsdUsdPrice);
      await TokenManager.addAcceptedToken(Tether.address, ClUsdUsd.address);

      //Depositing 1000 USDT as collateral
      const value = 1000000000;
      await Tether.mint(Vault.address, value);

      // Minting 500 euros against Tether
      const mint = ethers.utils.parseEther("500");
      await Vault.connect(user).mint(user.address, mint);
      expect(await Vault.undercollateralised()).to.equal(false);

      // Removing Tether as a collateral
      await TokenManager.removeAcceptedToken(USDTBytes);
      expect(await Vault.undercollateralised()).to.equal(true);

      // Removing collateral
      await Vault.connect(user).removeAsset(
        Tether.address,
        value,
        user.address
      );
      expect(await Tether.balanceOf(user.address)).to.equal(value);
    });
```

## Impact
All the stakers will loss on collateral

## Tools Used
Manual Review

## Recommendations
some recommendations are like seize that removed token from vault, if it's undercollateralized the vault or prevent removal of that token


