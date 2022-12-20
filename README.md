# bike_fault
Generate BIKE public key from faulted (or unfaulted) secret key

## Flags
- The flag `KEYPAIR=1` can be set to generate a binary that takes a secret key argument as hexadecimal string and outputs the derived public key.
- The flag `LEVEL` can be set to either 1, 3, 0, 10. The last two currently only work in combination with `KEYPAIR`.