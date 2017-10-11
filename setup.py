from setuptools import setup
import sys

try:
    from babel.messages import frontend as babel
except ImportError:
    print("Babel is not installed, you can't localize this package")
    cmdclass = {}
else:
    cmdclass = {
        'compile_catalog': babel.compile_catalog,
        'extract_messages': babel.extract_messages,
        'init_catalog': babel.init_catalog,
        'update_catalog': babel.update_catalog
    }


version = '0.0.1'

requires = [
    'eduid_actions>=0.1.0',
    'eduid_userdb>=0.3.0',
    'python-u2flib-server>=5.0.0',
]

if sys.version_info[0] < 3:
    # Babel does not work with Python 3
    requires.append('Babel==1.3')
    requires.append('lingua==1.5')

idp_extras = [
]

am_extras = [
]

actions_extras = [
    'setuptools>=2.2',
]

test_requires = [
    'WebTest==2.0.15',
    'mock==1.0.1',
]


testing_extras = test_requires + [
    'nose==1.3.3',
    'coverage==3.7.1',
    'nosexcover==1.0.10',
]

long_description = (
    open('README.txt').read()
)

setup(name='eduid_action.mfa',
      version=version,
      description="Multi-factor authentication plugin for eduid-actions",
      long_description=long_description,
      # Get more strings from
      # http://pypi.python.org/pypi?%3Aaction=list_classifiers
      classifiers=[
        "Programming Language :: Python",
        ],
      keywords='',
      author='Fredrik Thulin',
      author_email='fredrik@thulin.net',
      url='https://github.com/SUNET/',
      license='bsd',
      packages=['eduid_action.mfa'],
      package_dir = {'': 'src'},
      namespace_packages=['eduid_action'],
      include_package_data=True,
      zip_safe=False,
      cmdclass=cmdclass,
      install_requires=requires,
      extras_require={
          'idp': idp_extras,
          'actions': actions_extras,
          'testing': testing_extras,
          },
      entry_points={
          'eduid_actions.action':
                    ['mfa = eduid_action.mfa.action:MFAPlugin'],
          'eduid_actions.add_actions':
                    ['mfa = eduid_action.mfa.idp:add_mfa_actions'],
          },
      )
