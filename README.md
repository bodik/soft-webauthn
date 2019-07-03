# Python software webauthn token

[![Build Status](https://travis-ci.org/bodik/soft-webauthn.svg?branch=master)](https://travis-ci.org/bodik/soft-webauthn)

Package is used for testing webauthn enabled web applications.
SoftWebauthnDevice is deliberately mixing some client and authenticator
behavior, the interface exported mimic navigator.credentials create() and get()
functions.


## Development

```
git clone https://gitlab.flab.cesnet.cz/bodik/soft-webauthn
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
