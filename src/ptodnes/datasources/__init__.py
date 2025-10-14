from ptodnes.datasources.datasource import Datasource
import glob
from os.path import dirname, basename, isfile, join

modules = glob.glob(join(dirname(__file__), "*.py"))
__all__ = [basename(f)[:-3]
           for f in modules
           if isfile(f)
           and not f.endswith('__init__.py')
           and not f.startswith('_')]
from ptodnes.datasources import *
__subclasses = Datasource.__subclasses__()

datasources = {cls.__name__: cls() for cls in __subclasses}
names = [cls.__name__ for cls in __subclasses]
