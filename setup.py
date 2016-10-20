import io

from setuptools import find_packages, setup

long_description = (
    io.open('README.rst', encoding='utf-8').read() + '\n\n' +
    io.open('CHANGES.rst', encoding='utf-8').read())

setup(
    name='more.jwtauth',
    version='0.8',
    description="JWT Access Auth Identity Policy for Morepath",
    long_description=long_description,
    author="Morepath developers",
    author_email="morepath@googlegroups.com",
    keywords='morepath JWT identity authentication',
    license="BSD",
    url="https://github.com/morepath/more.jwtauth",
    namespace_packages=['more'],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Environment :: Web Environment",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        'Development Status :: 5 - Production/Stable'
    ],
    install_requires=[
        'morepath >= 0.16.1',
        'PyJWT == 1.4.2',
    ],
    extras_require=dict(
        crypto=['cryptography == 1.5.2'],
        test=[
            'pytest >= 2.9.1',
            'pytest-remove-stale-bytecode',
            'WebTest >= 2.0.14',
        ],
        pep8=[
            'flake8',
            'pep8-naming',
        ],
        coverage=[
            'pytest-cov',
        ],
    ),
)
