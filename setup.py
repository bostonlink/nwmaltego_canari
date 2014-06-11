from setuptools import setup, find_packages

setup(
    name='nwmaltego_canari',
    author='bostonlink',
    version='1.0',
    author_email='bostonlink@pentest-labs.org',
    description='Netwitness - Maltego Integration Project Ported to Canari Framework',
    license='GPL',
    packages=find_packages('src'),
    package_dir={ '' : 'src' },
    zip_safe=False,
    package_data={
        '' : [ '*.gif', '*.png', '*.conf', '*.mtz', '*.machine' ] # list of resources
    },
    install_requires=[ 'requests'
        # Name of packages required for easy_install
    ],
    dependency_links=[
        # custom links for the install_requires
    ]
)