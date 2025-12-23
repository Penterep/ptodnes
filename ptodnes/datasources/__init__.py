from ptodnes.datasources.datasource import Datasource

import pkgutil
import importlib

def load_datasource(name=None, verbose = True):
    Datasource.verbose = verbose
    if name is None:
        for module_info in pkgutil.iter_modules(__path__):
            module_name = module_info.name
            if module_name == 'datasource':
                continue
            importlib.import_module(f"{__name__}.{module_name}")
    else:
        for module_info in pkgutil.iter_modules(__path__):
            module_name = module_info.name
            if module_name == name:
                importlib.import_module(f"{__name__}.{module_name}")

def list_datasources():
    def inner():
        for module_info in pkgutil.iter_modules(__path__):
            if module_info.name == 'datasource':
                continue
            yield module_info.name
    return [x for x in inner()]

datasources = Datasource.loaded_datasource
names = Datasource.loaded_datasource.keys()