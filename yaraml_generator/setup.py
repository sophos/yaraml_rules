import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="yaraml-joshuasaxe-sophos-ai",
    version="0.0.1",
    author="Joshua Saxe",
    author_email="joshua.saxe@sophos.com",
    description="",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://ai.sophos.com",
    packages=setuptools.find_packages(),
    install_requires=[
    "networkx>=1.11",
    "joblib>=0.14.1",
    "numpy>=1.13.3",
    "scipy>=0.19.0",
    "pefile>=2019.4.18",
    "scikit_learn>=0.23.2"
    ],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: Affero License",
    ],
    python_requires='>=3.6',
    entry_points={
    'console_scripts': [
        'yaraml = yaraml.__main__:main'
    ]
    },
)
