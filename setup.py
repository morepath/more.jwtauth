from setuptools import find_packages, setup

long_description = (
    open("README.rst", encoding="utf-8").read()
    + "\n\n"
    + open("CHANGES.rst", encoding="utf-8").read()
)

setup(
    name="more.jwtauth",
    version="0.14",
    description="JWT Access Auth Identity Policy for Morepath",
    long_description=long_description,
    author="Morepath developers",
    author_email="morepath@googlegroups.com",
    keywords="morepath JWT identity authentication",
    license="BSD",
    url="https://github.com/morepath/more.jwtauth",
    namespace_packages=["more"],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Environment :: Web Environment",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Development Status :: 5 - Production/Stable",
    ],
    install_requires=["morepath >= 0.19", "PyJWT == 2.8.0"],
    extras_require=dict(
        crypto=["cryptography >= 3.4.0"],
        test=[
            "pytest >= 2.9.1",
            "pytest-remove-stale-bytecode",
            "webtest",
            "pygments",
        ],
        coverage=["pytest-cov"],
        lint=[
            "black == 22.3.0",
            "flake8 == 4.0.1",
            "pyupgrade == 2.34.0",
            "isort == 5.10.1",
        ],
    ),
)
