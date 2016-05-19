import io

from setuptools import find_packages, setup

long_description = (
    io.open('README.rst', encoding='utf-8').read() + '\n\n' +
    io.open('CHANGES.rst', encoding='utf-8').read())

setup(
    name='more.jwtauth',
    version='0.6',
    description="JWT Access Auth Identity Policy for Morepath",
    long_description=long_description,
    author="Henri Hulski",
    author_email="henri.hulski@gazeta.pl",
    keywords='morepath JWT identity authentication',
    license="BSD",
    url="https://github.com/morepath/more.jwtauth",
    namespace_packages=['more'],
    packages=find_packages(),
    include_package_data=True,
    zip_safe=False,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
        "Topic :: Internet :: WWW/HTTP",
        "Topic :: Internet :: WWW/HTTP :: Dynamic Content",
        "Topic :: Internet :: WWW/HTTP :: WSGI",
        "Topic :: Software Development :: Libraries :: Application Frameworks",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    install_requires=[
        'setuptools',
        'morepath >= 0.14',
        'PyJWT == 1.4.0',
    ],
    extras_require=dict(
        crypto=['cryptography == 1.3.1'],
        test=['pytest >= 2.9.1',
              'pytest-cov',
              'WebTest'],
    ),
)
