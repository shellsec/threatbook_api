#!/usr/bin/env python
# -*- coding:utf-8 -*-

import  io
from setuptools import setup, find_packages

setup(

    name="threatbook_API",
    version="0.1.3",
    url="https://github.com/li010101/threatbook_api.git",
    author="li010101",
    author_email="liyaohui54@gmail.com",
    long_description=io.open('README.rst',encoding='UTF-8').read(),
    license = "MIT Licence",
    packages=find_packages(),
    install_requires = ["requests"]
)