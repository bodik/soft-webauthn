# Python software webauthn token

[![Build Status](https://travis-ci.org/bodik/soft-webauthn.svg?branch=master)](https://travis-ci.org/bodik/soft-webauthn)

Package is used for testing webauthn enabled web applications. The use-case is
authenticator simulation during web application development CI, eg. FIDO2 token
emulation during registration and authentication process.

`SoftWebauthnDevice` class is deliberately mixing some client and authenticator
behavior, the interface exported mimic navigator.credentials create() and get()
functions. Note that communication protocol between *Client* and *Relaying
Party* is out-of-scope of Webauthn specification as well as credential storage
and it's association with the user identity.

Example usage code can be found in `tests/test_interop.py` (Token/Client vs RP
API) and `tests/test_example.py` (Token/Client vs RP HTTP).  Despite internal
usage of `yubico/python-fido2` package, the project should be usable againts
other RP implementations as well.

## References

* https://w3c.github.io/webauthn
* https://webauthn.guide/
* https://github.com/Yubico/python-fido2

## Development

```
git clone https://github.com/bodik/soft-webauthn
cd soft-webauthn
ln -s ../../git_hookprecommit.sh .git/hooks/pre-commit

# OPTIONAL, create and activate virtualenv
make venv
. venv/bin/activate

# install dependencies
make install-deps

# profit
make lint
make test
make coverage
```
