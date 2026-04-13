from setuptools import setup, find_packages
from ptodnes._version import __version__
 
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()
 
setup(
    name="ptodnes",
    version=__version__,
    description="OSINT Domain Name Enumeration System",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="GPLv3",
    authors=[
        "Penterep <info@penterep.com>",
        "Ondrej Dohnal <xodhna45@vutbr.cz>",
    ],
    author="Penterep",
    author_email="info@penterep.com",
    url="https://www.penterep.com",
    project_urls={
        "Homepage":   "https://www.penterep.com",
        "Source":     "https://github.com/Penterep/ptodnes",
        "Bug Reports": "https://github.com/Penterep/ptodnes/issues",
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "Topic :: Security",
        "Topic :: System :: Networking",
        "Topic :: System :: Networking :: Monitoring",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
        "Programming Language :: Python :: 3",
        "Operating System :: POSIX :: Linux",
        "Environment :: Console",
    ],
    keywords=[
        "network",
        "scanner",
        "osint",
        "security",
        "vulnerability-detection",
        "penetration-testing",
        "dns",
    ],
    packages=find_packages(),
    python_requires=">3.11, <=3.15",
    install_requires=[
        "aiodns>=4.0.0,<5.0.0",
        "aiohttp>=3.13.0,<4.0.0",
        "aiopg>=1.4.0,<2.0.0",
        "pyyaml>=6.0.0,<7.0.0",
        "ptlibs>=1.0.0,<2.0.0",
        "aiofiles>=25.1.0,<26.0.0",
        "punycode>=0.2.0,<1.0.0",
    ],
    extras_require={
        "docs": [
            "mkdocs>=1.6.1,<2.0.0",
            "sphinx>=8.2.3,<9.0.0",
        ],
        "test": [
            "pytest>=8.3.3,<9.0.0",
            "pytest-cov>=6.0.0,<7.0.0",
            "flake8>=7.1.1,<8.0.0",
            "pylint>=3.3.1,<4.0.0",
            "pytest-md-report>=0.6.2,<1.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "ptodnes=ptodnes.__main__:__main__",
        ],
    },
)
