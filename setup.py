import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="collect-bin-deps",
    version="0.0.1",
    author="Frank Richter",
    author_email="frank.richter@gmail.com",
    description="A tool to collect binary dependencies",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/res2k/collect-bin-deps",
    packages=[],
    py_modules=["collect-bin-deps"],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: zlib/libpng License",
        "Operating System :: OS Independent",
    ],
    python_requires='>=3.6',
    install_requires=['pefile', 'pyelftools'],
    scripts=['collect-bin-deps.py'],
)
