from setuptools import setup
import sys

if sys.version_info < (3, 8):
    raise RuntimeError("aiohttp 4.x requires Python 3.8+")

setup(
    name='topscore',
    version='0.0.2',
    packages=['topscore'],
    url='https://github.com/cherianb59/topscore',
    author='Ben Cherian, Ian Marlier',
    author_email='',
    description='Python API Client for TopScore',
    
)
