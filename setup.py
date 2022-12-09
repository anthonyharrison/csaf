from setuptools import find_packages, setup

from csaf.version import VERSION

with open("README.md", encoding="utf-8") as f:
    readme = f.read()

with open("requirements.txt", encoding="utf-8") as f:
    requirements = f.read().split("\n")

setup_kwargs = dict(
    name='csaf-tool',
    version=VERSION,
    description='CSAF generator and analyser',
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/anthonyharrison/csaf",
    author='Anthony Harrison',
    author_email='anthony.p.harrison@gmail.com',
    maintainer='Anthony Harrison',
    maintainer_email='anthony.p.harrison@gmail.com',
    license='MIT',
    keywords=["security", "tools", "CSAF", "CSAF 2.0", "Vex" "DevSecOps", "vulnerabilities"],
    install_requires=requirements,
    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT',
        "Natural Language :: English",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
    ],
    python_requires=">=3.7",
    packages=find_packages(),
    entry_points={
        "console_scripts": [
            "csaf-tool = csaf.cli:main",
        ],
    },
)

setup(**setup_kwargs)
