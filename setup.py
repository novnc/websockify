from setuptools import setup

version = '0.14.0'
name = 'websockify'
long_description = open("README.md").read() + "\n" + \
    open("CHANGES.txt").read() + "\n"

setup(
    name=name,
    version=version,
    description="Websockify.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    classifiers=[
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
    ],
    python_requires='>=3.10',
    keywords='noVNC websockify',
    license='LGPLv3',
    url="https://github.com/novnc/websockify",
    author="Joel Martin",
    author_email="github@martintribe.org",
    packages=['websockify'],
    include_package_data=True,
    install_requires=[
        'numpy>=1.26.0',
        'requests>=2.32.0',
        'jwcrypto>=1.5.7',
        'redis>=5.0.0',
    ],
    zip_safe=False,
    entry_points={
        'console_scripts': [
            'websockify = websockify.websocketproxy:websockify_init',
        ]
    },
)
