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
        "joblib==0.17.0",
        "networkx==2.5",
        "numpy==1.21.0",
        "pefile==2019.4.18",
        "scikit-learn==0.23.2",
        "scipy==1.5.4"
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
