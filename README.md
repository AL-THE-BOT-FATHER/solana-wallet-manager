## Solana Wallet Manager

![image](https://github.com/user-attachments/assets/dccd44e0-7735-43be-937e-3fa3817d3c37)

The Solana Wallet Manager GUI application is a user-friendly interface designed for managing wallets and transactions on the Solana blockchain.

***Warning: wallets.json stores priv keys, handle this file carefully!!!***

```
Add Wallet:
Allows users to manually add wallets by entering a wallet name, public key, and private key.

Generate Wallet:
Generates a new wallet with a unique public and private key.
Prompts the user to assign a name to the generated wallet.

Remove Wallet:
Enables users to remove an existing wallet.
Checks the wallet's balance before removal.
Warns the user if the wallet has a non-zero balance and allows them to cancel the operation.

Check Balance:
Allows users to select a wallet and retrieve its balance in SOL.

Transfer SOL:
Tranfers SOL between wallets.
Requires the sender's private key and the receiver's public key.

Recover SOL:
Transfers all available SOL from one wallet to another.
Useful for consolidating funds into a primary wallet.
```

This project requires:

```pip install solders solana PyQt5```
