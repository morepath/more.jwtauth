import os, io
from setuptools import setup, find_packages

long_description = (
    io.open('README.rst', encoding='utf-8').read()
    + '\n' +
    io.open('CHANGES.txt', encoding='utf-8').read())

setup(name='more.jwtauth',
      version='0.2.dev0',
      description="JWT Access Auth Identity Policy for Morepath",
      long_description=long_description,
      author="Henri Schumacher",
      author_email="henri.hulski@gazeta.pl",
      keywords='morepath JWT identity authentication',
      license="BSD",
      url="https://github.com/henri-hulski/more.jwtauth",
      namespace_packages=['more'],
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      install_requires=[
          'setuptools',
          'morepath > 0.10',
          'PyJWT >= 1.1.0',
          'cryptography >= 0.8.2'
      ],
      extras_require=dict(
          test=['pytest >= 2.7.0',
                'pytest-cov',
                'WebTest'],
      ),
)
