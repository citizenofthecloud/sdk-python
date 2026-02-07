from setuptools import setup, find_packages

setup(
    name="citizenofthecloud",
    version="0.1.0",
    description="Identity and authentication SDK for autonomous AI agents",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="citizenofthecloud.com",
    url="https://github.com/citizenofthecloud/sdk-python",
    license="MIT",
    packages=find_packages(),
    python_requires=">=3.9",
    install_requires=[
        "cryptography>=41.0.0",
    ],
    extras_require={
        "fastapi": ["fastapi>=0.100.0"],
    },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security :: Cryptography",
        "Topic :: Software Development :: Libraries",
    ],
)
