
To run cli:
```uv run cli.py generate-keys --output-dir keys
uv run cli.py sign unsigned.pdf signed.pdf --key keys/private_key.pem --cert keys/certificate.pem --create-field
uv run cli.py verify signed.pdf --cert keys/certificate.pem```

To run GUI:
```uv run main.py```
