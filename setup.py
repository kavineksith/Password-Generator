from setuptools import find_packages, setup

setup(
    name="passforge",
    version="1.0.0",
    description="Industrial-grade asynchronous password and passphrase generator CLI",
    author="Kavin",
    packages=find_packages(include=["passforge", "passforge.*"]),
    python_requires=">=3.11",
    install_requires=["aiofiles>=23.2.1"],
    extras_require={"dev": ["pytest>=7.4.0", "pytest-asyncio>=0.21.0"]},
    entry_points={"console_scripts": ["passforge=passforge.cli.main:main"]},
)
