"""Setup for Azure Linux OVAL to OSV converter"""
from setuptools import setup, find_packages

setup(
    name='azurelinux-osv',
    version='0.1.0',
    description='Azure Linux OVAL to OSV format converter',
    author='OSV Schema Contributors',
    packages=find_packages(),
    python_requires='>=3.9',
    install_requires=[
        'requests>=2.25.0',
    ],
    extras_require={
        'validation': [
            'jsonschema>=4.0.0',
        ],
        'dev': [
            'jsonschema>=4.0.0',
            'pylint>=2.0.0',
            'yapf>=0.30.0',
        ],
    },
    entry_points={
        'console_scripts': [
            'convert-azurelinux=convert_azurelinux:main',
        ],
    },
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
    ],
)
