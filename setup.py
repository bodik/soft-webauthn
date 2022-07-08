import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='soft-webauthn',
    version='0.1.4',
    author='Radoslav Bodó',
    author_email='bodik@cesnet.cz',
    description='Python webauthn software authenticator',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/bodik/soft-webauthn',
    py_modules=['soft_webauthn'],
    install_requires=[
        'fido2>=1.0,<2.0',
        'cryptography'
    ],
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)
