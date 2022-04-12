#!/usr/bin/env python

"""The setup script."""

from setuptools import setup, find_packages

with open('README.rst') as readme_file:
    readme = readme_file.read()

with open('HISTORY.rst') as history_file:
    history = history_file.read()

requirements = [ ]

test_requirements = [ ]

setup(
    author="Akiva Berger",
    author_email='akiva10b@gmail.com',
    python_requires='>=3.6',
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    description="Django Shared Permissions allows users to share permissions checked in one service and pass the validated data via encryption to another service",
    install_requires=requirements,
    license="MIT license",
    long_description=readme + '\n\n' + history,
    include_package_data=True,
    keywords='django_shared_permissions',
    name='django_shared_permissions',
    packages=find_packages(include=['django_shared_permissions', 'django_shared_permissions.*']),
    test_suite='tests',
    tests_require=test_requirements,
    url='https://github.com/akiva10b/django_shared_permissions',
    version='0.1.0',
    zip_safe=False,
)
