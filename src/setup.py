import setuptools

# with open("README.md", "r", encoding="utf-8") as fh:
#     long_description = fh.read()

setuptools.setup(
    name="apm",
    version="0.0.1",
    author="skinnybeans",
    author_email="skinnybeans@gmail.com",
    description="Manage AWS permissions",
    long_description="nothing yet",
    # long_description_content_type="text/markdown",
    url="https://github.com/",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "."},
    packages=setuptools.find_packages(where="."),
    python_requires=">=3.10",
    entry_points={"console_scripts": ["apm = apm.cli:start"]},
)
