# Evil-JEA (Kerberos Edition)

A powerful WinRM client designed for interacting with JEA endpoints from Linux, now with **Kerberos ticket authentication** support.

## Features

- ✅ NTLM authentication (username/password)
- ✅ **Kerberos ticket authentication** (NEW!)
- ✅ Cross-domain trust support
- ✅ JEA bypass techniques (call/function operators)
- ✅ Reverse shell capabilities

## Installation

### From Source (Recommended for Kerberos support)

```bash
git clone https://github.com/boboaung1337/evil-jea
cd evil-jea
make install
make build
```

# Install system dependencies for Kerberos
sudo apt-get install -y libkrb5-dev gssapi

# Install Python dependencies
pip install gssapi krb5 pypsrp



