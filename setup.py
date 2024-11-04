from setuptools import setup, find_packages

setup(
    name="CS404 Crypto Locker",
    version="1.0.0",
    packages=find_packages(),
    install_requires=[
        "cryptography",
        "ttkbootstrap",
    ],
)
