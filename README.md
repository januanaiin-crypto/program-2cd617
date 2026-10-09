# Solana program

- Program id: `B9NvpqrBERJxPjku8JMKZTedYTKtTxQgrhpzkiAoRDv5` (Solana mainnet)

## Verifiable build

```bash
solana-verify build --library-name quantum_vault
solana-verify get-executable-hash target/deploy/quantum_vault.so
solana-verify get-program-hash -um B9NvpqrBERJxPjku8JMKZTedYTKtTxQgrhpzkiAoRDv5
```

The two hashes must be equal. The same build runs in this repository's "Verifiable build" workflow.
