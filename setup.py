import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='soft_webauthn',
    version='0.0.1',
    author='Radoslav Bodó',
    author_email='bodik@cesnet.cz',
    description='Python webauthn software authenticator',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/bodik/soft_webauthn',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: MIT License',
    ],
)
