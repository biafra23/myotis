# A Trustless Ethereum Wallet — Why It Matters

## The Problem Nobody Talks About

Every Ethereum wallet you have ever used — MetaMask, Rainbow, Trust Wallet, Coinbase Wallet — shares a dirty secret: it does not actually verify anything on its own. When you open your wallet and see your balance, that number did not come from the Ethereum network. It came from a server.

Specifically, it came from a **JSON-RPC server** — a centralised data provider that your wallet silently connects to in the background and asks: *"What is my balance? What are my transactions? Did my transfer go through?"* Your wallet takes the answer at face value and displays it to you. No verification. No proof. Pure trust.

This is the equivalent of calling your bank to ask what your balance is, and having no way to check whether they are telling you the truth.

---

## Who Controls These Servers?

A small number of companies operate the RPC servers that the vast majority of Ethereum wallets depend on. Infura and Alchemy together serve a substantial majority of all wallet traffic on Ethereum. Both are US-based, venture-funded, commercial enterprises.

This means:

**They can be pressured.** Governments can compel them to block certain addresses or return false data for specific users. This has already happened — in 2022, Infura and Alchemy both blocked access for users in certain jurisdictions following regulatory pressure, without any warning to wallet developers or users.

**They can go down.** When Infura experienced an outage in November 2020, MetaMask and most of the Ethereum ecosystem went dark simultaneously. A decentralised network was taken offline by the failure of a single company's servers.

**They can surveil you.** Every time your wallet refreshes, the RPC server learns your IP address, which addresses you control, what tokens you hold, and when you check them. This data is enormously valuable and there are no meaningful technical guarantees about how it is used or sold.

**They can lie — and for most data, you cannot tell.** For account balances, there is a partial remedy: a standard called `eth_getProof` allows an RPC provider to return a cryptographic proof alongside a balance, which the wallet can verify independently. Projects like Helios use this approach and are a genuine improvement over naive RPC usage. But this only covers a narrow slice of wallet data. Transaction history — the list of all transfers in and out of your address — carries no such proof. There is no standard RPC mechanism that lets you verify that a provider has returned *all* your transactions rather than a conveniently edited subset. And crucially, even `eth_getProof` only proves that data is consistent with a given block hash — if the provider feeds you a false block hash to begin with, the proof is worthless. Helios addresses this by using sync committees to establish a trusted block hash independently. The remaining problem with RPC-based verification is not correctness of individual data points — it is availability, completeness, and surveillance, which no proof mechanism addresses.

**They can deny you service.** Your wallet works because a company decided to let it work. That company can change its terms, go bankrupt, get acquired, or simply decide that certain users are not welcome. When that happens, your wallet stops working — even though the Ethereum network itself is running perfectly.

---

## This Is Not What Ethereum Was Built For

Ethereum was designed as a permissionless, trustless, censorship-resistant network. The whole point is that no single party controls it. And yet the dominant user experience routes every single interaction through a centralised chokepoint, recreating exactly the dependency on trusted intermediaries that the technology was meant to eliminate.

This is not a theoretical concern. It is the current reality for hundreds of millions of wallet users.

---

## Bitcoin Solved This 16 Years Ago

It is worth noting that Bitcoin has had an answer to this problem since 2008. Satoshi Nakamoto described it in section 8 of the original Bitcoin whitepaper: **Simplified Payment Verification**, or SPV.

SPV allows a Bitcoin wallet to verify its own transactions cryptographically, using only a small amount of data downloaded directly from the Bitcoin peer-to-peer network. The wallet does not need to trust any server. It checks the mathematics itself. Wallets like Electrum have used this approach for over a decade, running comfortably on ordinary laptops and mobile phones.

Bitcoin users who care about self-sovereignty have had access to trustless light clients for the entire history of the ecosystem. Ethereum users, despite operating a far more sophisticated network, have not. Until now.

---

## What This Library Is

Myotis is a wallet engine for a trustless Ethereum wallet — it runs as an Android app, an iOS app and a desktop app, and embeds as a library (a Node.js addon for Electron hosts, an iOS framework). It gives wallet developers everything they need to show users their current balances and token holdings, resolve names, and create and broadcast new transactions — all without connecting to a centralised server at any point — and exposes it as a standard JSON-RPC endpoint an unmodified wallet can use (see the [README](../README.md) for what is built and [Implementation Status](implementation-status.md) for what remains). The library handles the peer-to-peer networking, cryptographic verification, and consensus tracking directly, so the wallet built on top of it inherits all of those properties without having to implement them itself.

## What This Library Does Differently

Rather than querying a centralised server, this library connects directly to the Ethereum peer-to-peer network and retrieves and **verifies** all data cryptographically. (The rest of this section is written as the design intent; the parts still ahead of the implementation are the transaction-history index and its balance reconciliation, and Tor routing beyond account reads.)

**Balances will be proven, not reported.** The library will fetch ETH balances and ERC-20 token holdings with cryptographic proofs that link the data back to a trusted chain state. If the data does not match the proof, it will be rejected. No server will be able to fabricate a balance that passes verification.

**Transaction history will be verified, not trusted — with one caveat.** Transaction history will be assembled from a decentralised index distributed over IPFS, and each individual transaction will be verified against the block it was included in. The block itself will be verified against a chain of cryptographic commitments going back to the current consensus. What cannot be proven cryptographically is *completeness* — that the index contains every transaction that ever touched your address, with none omitted. To mitigate this, the wallet will reconcile your computed balance against your cryptographically verified on-chain balance. If the two do not match, the wallet will warn you that your transaction history may be incomplete. This is the same limitation that affects any wallet relying on an address index rather than scanning every block independently — including conventional RPC-based wallets, which have no reconciliation mechanism at all.

**The chain state will be trusted through mathematics, not authority.** The library will track Ethereum's consensus by participating in the beacon chain's sync committee protocol — the same mechanism Ethereum itself uses for light client security. The trust assumption is that a supermajority of a randomly selected set of validators are honest. This is the same assumption the entire Ethereum network rests on.

**Transactions will be submitted directly to peers.** Signed transactions will be broadcast directly to the Ethereum peer-to-peer network, not routed through an RPC provider. No intermediary will be able to block, censor, or delay your transactions at the infrastructure level.

**Surveillance exposure will be significantly reduced.** Conventional RPC providers see your IP address alongside every address you query, every time you open your wallet, and retain that data indefinitely. This library will distribute queries across random peers on the public network — no single entity will accumulate a longitudinal record of your activity. Balance queries can additionally be made against a range of addresses rather than a single one, making it harder for any individual peer to determine which address is actually yours. For users who want stronger privacy guarantees, state queries in particular could be routed through Tor, reducing IP exposure to individual peers. However, multiple queries made within the same Tor circuit may still be correlatable, so this is a mitigation rather than a complete solution.

---

## What This Will Mean in Practice

| | Conventional RPC-based wallet | This library |
|---|---|---|
| Balance source | Centralised server | Cryptographic proof from the network |
| Can be censored | Yes — by RPC provider | No — direct peer-to-peer |
| Surveillance risk | High — provider logs IP + addresses | Reduced — queries distributed across random peers, range obfuscation possible, state queries Tor-friendly |
| Works if provider goes down | No | Yes |
| Works under regulatory pressure | Depends on provider's jurisdiction | Yes |
| Verifies data independently | No | Yes |
| Requires permission to use | Yes — subject to provider ToS | No |

---

## Who This Is For

This library is primarily aimed at developers building Ethereum wallets and applications who want to offer their users genuine self-sovereignty — not the appearance of it.

It is also directly relevant to:

- **Privacy-sensitive users** who do not want their financial activity logged by commercial infrastructure providers
- **Users in jurisdictions** where access to crypto services is restricted or at risk of restriction
- **Developers building in adversarial environments** where infrastructure availability cannot be guaranteed
- **Anyone who believes** that the point of a decentralised network is to actually be decentralised

---

## The Bigger Picture

The irony of the current situation is that Ethereum — a network specifically designed to remove the need for trusted intermediaries — has, at the wallet layer, reintroduced a trusted intermediary that is more centralised and more powerful than most of the institutions it was meant to replace.

A handful of companies now sit between hundreds of millions of users and the network they think they are using. Those companies are subject to legal pressure, commercial incentives, and operational failures. Users have no way to verify what they are being told, and no recourse when it goes wrong.

This does not have to be the case. The cryptographic tools to fix it exist, and this library will put them to work — bringing genuine trustless verification to Ethereum's full complexity of accounts, tokens, and smart contracts.

A wallet that verifies its own data is not just more secure. It is more honest about what a self-custodial wallet is supposed to mean.
