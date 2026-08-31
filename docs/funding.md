# Funding / crypto support

The SecHelix VNext website ships with a support page whose public receive
addresses are maintained in the private website repository. The public
framework repository intentionally contains no website or wallet configuration.

## Option A — direct crypto addresses

Maintainers should add only **public receiving addresses** to the private
website configuration, verify the rendered asset/network pair and QR value
locally, then publish through the protected website pipeline.

Example:

```js
window.SECHELIX_SUPPORT = {
  providerLabel: "Donate with crypto",
  providerUrl: "",
  wallets: {
    usdt: {
      label: "USDT",
      network: "TRON (TRC20)",
      address: "YOUR_PUBLIC_RECEIVING_ADDRESS"
    },
    btc: {
      label: "Bitcoin",
      network: "BTC",
      address: "YOUR_PUBLIC_RECEIVING_ADDRESS"
    }
  }
};
```

Do not publish many networks at first. A small, clearly labeled set reduces donor mistakes.

## Option B — NOWPayments donation link/widget

NOWPayments currently documents donation buttons, donation links, and an embeddable donation widget. Its public product documentation also advertises multi-asset crypto support and payment-widget fiat-to-crypto capabilities.

Recommended integration sequence:

1. create the provider account;
2. set the payout wallet(s);
3. create a dedicated API key/payment or donation link for SecHelix;
4. test with a small amount;
5. put the **public donation URL** into the private website deployment configuration;
6. keep private credentials/webhook secrets outside the static site and repository.

The SecHelix website intentionally uses a provider **link** first rather than
embedding secret-bearing backend logic.

## Card-to-crypto goal

If you want supporters to pay with a card/fiat while you receive crypto, evaluate the provider's current fiat-to-crypto/payment-widget availability, supported countries, KYC requirements, chargeback model, minimums, and settlement network before launch. Treat this as a payment-provider feature, not something SecHelix should implement itself.

## Security

Never commit:

- seed phrases;
- private keys;
- exchange passwords;
- API secrets that authorize withdrawal;
- webhook signing secrets;
- KYC documents.

Public receiving addresses and public donation links are acceptable to publish after you verify them.

## Trust / anti-phishing

Once the custom domain is live:

- publish donation addresses only on the official domain and repository;
- link the domain from GitHub and GitHub from the domain;
- pin a checksum/signature or release note when changing addresses;
- warn donors to verify the blockchain/network before sending funds.
