# Python software webauthn token

Package is used for testing webauthn enabled web applications.


## Development

```
git clone https://gitlab.flab.cesnet.cz/bodik/soft_webauthn
cd soft_webauthn
ln -s ../../bgit_hookprecommit.sh .git/hooks/pre-commit

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
