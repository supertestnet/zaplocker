![](https://supertestnet.github.io/swap-service/zaplocker-logo.png)

Non-custodial lightning address server with base layer support too

# How to try it

Go here: https://zaplocker.com

# Video

[![](https://supertestnet.github.io/swap-service/zaplocker-with-youtube-logo.png)](https://www.youtube.com/watch?v=5LYt4H6xA-g)

# Four problems zaplocker solves

(1) End users don't want to run a web server. But lightning addresses don't work without a web server where wallets can request lightning invoices. Zaplocker allows a service provider to run a web server on their users' behalf.

(2) Lightning address servers usually take custody of user funds. Due to problem #1, most users rely on the following public lightning address servers: getalby.com, stacker.news, and walletofsatoshi.com. But the default mode of these servers is custodial. Custodying user funds introduces many costs and risks for lightning address servers, including: risk of theft, risk of accidental loss, cost of complying with financial custody laws, and risk of arrest if you do not comply with those laws. Zaplocker lets anyone provide lightning addresses to their users without taking custody of user funds, thus reducing those risks.

(3) Avoiding third-party custody usually means running an always-on lightning node. Due to problem #2, some lightning address servers have a feature that lets users receive funds directly to their own lightning node. This trades off the custody problem for an always-on problem: if your user only has a lightning wallet on their phone, it has to be "on" (i.e. open) or it can't give the lightning address server a lightning invoice when someone requests one. Meaning many payments just fail before they even start. Zaplocker lets users avoid third-party custody *without* an always-on lightning node.

(4) Lightning addresses don't usually work on the base layer. Many people want their payments to go straight to a cold storage wallet or an exchange account or a multisig vault. Lightning addresses are, as the name implies, lightning tech, which means they send funds to a "hot wallet" exposed to the internet -- because *all* lightning wallets are exposed to the internet. Zaplocker gives users a choice: do you want to receive your payments into a lightning wallet or a bitcoin address on the base layer? Which means lightning addresses, for the first time, support the base layer.

# How it works

Zaplocker takes my old [hodl contracts](https://github.com/supertestnet/hodlcontracts) idea and applies it to lightning addresses. A user creates an account with zaplocker by logging in with nostr and choosing a username. When they log in, they -- in the background -- create a bunch of lightning payment hashes and share them with the server. The server then shows the user their lightning address and a "pending payments" dashboard.

If someone requests an invoice from that user, zaplocker creates a "hodl invoice" using one of the user's payment hashes. This means zaplocker cannot settle any payment sent using that invoice. Zaplocker simply does not have the keys, the user alone has them. If the server detects that the sender *tried* to pay that hodl invoice, it does not fail the payment right away. Instead, it uses nostr to notify the user that they have a pending payment and invites them to visit zaplocker to settle it within the next 16 hours. When the user arrives at zaplocker, they can see their pending payment and two options: settle on lightning or settle on the base layer.

To settle on lightning, the user must create a "custom lightning invoice" whose payment hash matches the one held by the server. Few lightning wallets let you do this, but LND does. Users can use that for now, and I am currently in talks with other lightning wallet developers to add support for custom lightning invoices. If the user supplies a compatible lightning invoice for the same amount as the one held by the server (minus a service fee), zaplocker will pay it. This will give the server a "proof of payment" which consists of the very key they need in order to settle the sender's payment. Settling that payment completes the circuit -- the end user got paid, zaplocker got its service fee, and zaplocker never had custody of the user's funds.

To settle on the base layer, the user must say what bitcoin address they want their money to end up in. The user will then coordinate a submarine swap with the server. The server deposits the right amount of money (minus a service fee) to a "swap address" on bitcoin's base layer, and the user sweeps the money out of that address into the bitcoin address they picked. But the user can only sweep the money by revealing to the server the key the server needs in order to settle the sender's payment. (If the user neglects to reveal that key, the server gets their deposit back after 10 bitcoin blocks.) Assuming the user sweeps their money, that completes the circuit -- the end user got paid, zaplocker got its service fee, and zaplocker never had custody of the user's funds.

# Other cool things about zaplocker

- Zaplocker is free and open source software. You can run it yourself to provide users of your service with a lightning address without taking custody of user funds. The zaplocker name as well as the software is fully released into the public domain, with no rights reserved. If you're a developer, go hog wild! Make it your own! Do it your way, with your own spin, on your own server!
- Zaplocker supports zaps. If you add your zaplocker address to your nostr account, people can zap you on nostr-based social networks. Zaplocker sends out a zap receipt when a lightning payment goes into a pending state, and zappy apps can detect this receipt to show a green checkmark to their users -- without waiting for the recipient to come online and settle the payment.

# Fixing the man in the middle

There is an attack that lightning address servers such as zaplocker can do to steal funds from a sender. Show the sender a lightning invoice where the *server* holds the keys instead of the recipient, then settle the sender's payment and never tell the intended recipient about it. Zaplocker proposes solving this problem by signing and broadcasting a bunch of nostr messages at various stages of a payment. This solution is implemented in zaplocker. 

When a user logs in for the first time, they create a bunch of payment hashes for the server to use when generating lightning invoices. Zaplocker has the user *sign their payment hashes* using their nostr public key and displays the user's signature and nostr public key on the endpoint where invoices are generated. Sending wallets can *validate that signature* before sending the payment, that way the sender knows the user has the keys.

However, this solution is only partial: wallets need to implement it, and even if they do implement it, the server can still steal funds by reusing a "used" payment hash once they know its preimage. This is because once a payment hash has been "used" the server knows the key now. If they "reuse it," the signature on that payment hash will still be valid, but now the server can use the key -- which they now know -- to settle the payment and never tell the intended recipient about it. To fix that, zaplocker proposes doing this (which I have not implemented yet): when a sender sends a payment, they should send a nostr note announcing that that payment hash has been "used up."

This note should be sent publicly to a set of nostr relays selected and signed by the recipient, and this note should reference a public key created by treating the payment hash as a private key and deriving the corresponding public key. Senders can request this message from the user's nostr relays before sending a payment, and refuse to send the payment if they detect a message from a previous sender stating that the payment hash was used. This solution will require zaplocker to *expand* the amount of info signed by the user when they log in. Namely, they will need to sign a message stating what relays to send these notes to, and zaplocker will need to display that message as well as the user's signature so that senders can validate it and know what relays to listen for messages on. Also, sender wallets will need to implement the message-sending function and validate that at least one of those relays is still working.

However, even *this* solution is only partial. Aside from the fact that neither zaplocker nor any wallets have implemented it (yet), the server can *still* steal funds by forwarding a smaller amount of funds to the user than the amount intended by the sender, without telling the recipient about the difference. To fix that, zaplocker proposes that the sender's note should *also* contain the invoice generated by the server. The user's browser should then *listen for that note* before settling a payment, and ensure (1) such a note exists and (2) the amount in the invoice is equal to the amount being forwarded by the server (minus the agreed-upon service fees). Zaplocker does not implement this solution yet, so it is only a proposal. Until it is implemented, users must trust the zaplocker server not to steal money in any of the above mentioned ways.
