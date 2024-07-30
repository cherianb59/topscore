from setuptools import setup
import sys

if sys.version_info < (3, 8):
    raise RuntimeError("aiohttp 4.x requires Python 3.8+")

setup(
    name='topscore',
    version='0.0.1',
    packages=['topscore'],
    url='https://github.com/cherianb59/topscore',
    license='',
    author='Ben Cherian, Ian Marlier',
    author_email='',
    keywords="topscore usetopscore ultimate frisbee",
    description='Python API Client for TopScore',
    install_requires=[
    	'requests',
        'aiohttp',
        'beautifulsoup4'
    	]
)
