from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="pip-guardian",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "requests",
        "pyyaml",
    ],
    entry_points={
        "console_scripts": [
            "guardian=guardian.cli:main",
        ],
    },
    author="Anant Dhavale",
    author_email="anantdhavale@gmail.com",
    description="Stops malicious PyPI packages before installation",
    long_description=long_description,
    long_description_content_type="text/markdown",
    license="MIT",
    url="https://github.com/AnantDhavale/pip-guardian",
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Topic :: Security",
    ],
    python_requires=">=3.9",
)
