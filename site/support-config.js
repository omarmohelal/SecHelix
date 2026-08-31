// Public donation configuration only.
// NEVER put private keys, seed phrases, exchange credentials, webhook secrets,
// API keys, or withdrawal credentials in this file.
//
// IMPORTANT: exchange deposit addresses can change. If you rotate an address,
// update this file and the official SecHelix domain together.

window.SECHELIX_SUPPORT = {
  providerLabel: "Donate with crypto",
  providerUrl: "",
  wallets: {
    usdt_trc20: {
      label: "USDT",
      network: "TRON (TRC20)",
      address: "TTDXsESKuGBvLfSStWcFKNMTUSwD5b7Wxj",
      note: "Send USDT only on TRON (TRC20)."
    },
    usdt_erc20: {
      label: "USDT",
      network: "Ethereum (ERC20)",
      address: "0x54283165637f8f9a4ec3a394dc1a7ff5379fd849",
      note: "Send USDT only on Ethereum (ERC20)."
    },
    usdt_bep20: {
      label: "USDT",
      network: "BSC (BEP20)",
      address: "0x54283165637f8f9a4ec3a394dc1a7ff5379fd849",
      note: "Send USDT only on BSC (BEP20). Do not use opBNB."
    },
    btc: {
      label: "Bitcoin",
      network: "BTC",
      address: "bc1q3zr0nux5s4xlzsykh9v9md76yhvd7dd2mrn8z8j48fymanap00tqvw4hxs"
    },
    ltc: {
      label: "Litecoin",
      network: "LTC",
      address: "ltc1qw0nlgtgtuhr4jvzt850hhfehf54klj28sz8suv7uurun2mwu2tnsccnq7l"
    },
    eth: {
      label: "Ethereum",
      network: "ETH",
      address: "0x20c4dbc5a7c386f29cb96efca10eaf253688ea4a"
    },
    sol: {
      label: "Solana",
      network: "SOL",
      address: "8efDtfcKPZVPWaww2PqGDTPpzzkXL4rxNkuj89qZT4eM"
    }
  }
};