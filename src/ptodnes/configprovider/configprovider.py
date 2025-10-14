import tomllib
import pathlib
import os

from ptodnes.metaclasses import Singleton


class ConfigProvider(metaclass=Singleton):
    """
    Singleton class that provides access to configuration settings.
    """
    @property
    def config_file(self):
        """
        Config file location.
        """
        return self.__config_file

    @config_file.setter
    def config_file(self, value):
        self.__config_file = value
        if not pathlib.Path.exists(pathlib.Path(value)):
            with open(value, "a", encoding="utf8", newline="") as _: pass
        with open(value, "rb") as f: self.__config = tomllib.load(f)

    @property
    def config(self):
        """
        Configuration read from configuration file.
        """
        return self.__config

    def __init__(self, config_file = os.path.join(pathlib.Path.home(), "ptodnes.toml")):
        """
        :param config_file: config file path
        """
        self.__config_file = config_file
        if not pathlib.Path.exists(pathlib.Path(config_file)):
            with open(config_file, "a", encoding="utf8", newline="") as _: pass
        with open(config_file, "rb") as f: self.__config = tomllib.load(f)

    def get_config(self, section: str) -> dict:
        """
        Get config for specific section.
        :param section: section name
        :return: config
        """
        return self.__config.get(section, {})
