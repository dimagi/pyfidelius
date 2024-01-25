from setuptools import setup, find_packages

setup(
    name='fidelius',
    version='0.1',
    description='A Python library for cryptographic operations',
    author='Sravan Reddy',
    author_email='sreddy@dimagi.com',
    url='https://github.com/dimagi/pyFidelius',
    py_modules=["fidelius"],
    install_requires=[
        'fastecdsa>=2.3.0',
        'pycryptodome>=3.19.1',
    ],
)
