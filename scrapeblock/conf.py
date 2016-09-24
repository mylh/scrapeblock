import os
import yaml
from logbook import Logger

log = Logger(__name__)


class ImrpoperlyConfigured(Exception):
    pass


class LazySettings(object):

    def __init__(self):
        self.load_path = 'config.yml'
        self._settings_dict = {
            'log': {
                'level': 'notice',
                'screen': True,
                'path': '/tmp/scrapeblock.log',
                'rotate': 5,
                },
            }
        self._loaded = False

    def _setup(self):
        path = os.path.expanduser(self.load_path)
        log.debug('Reading settings from %s' % path)
        try:
            with open(path, 'r') as config_file:
                self._settings_dict.update(
                    yaml.load(config_file)
                )
        except IOError as e:
            log.warn('Error reading config file %s: %s' % (path, e))
        except Exception as e:
            log.warn('Error in settings: %s' % e)
        self._loaded = True

    def get(self, name, default=None):
        """Return setting understanding dotted.location.path"""
        if not self._loaded:
            self._setup()
        val = self._settings_dict
        for key in name.split('.'):
            val = val.get(key)
            if val is None:
                break
        return val if val is not None else default

    def __getattr__(self, name):
        if not self._loaded:
            self._setup()
        val = self._settings_dict
        return val.get(name)

    @property
    def configured(self):
        """
        Return True if the settings have already been configured.
        """
        return self._loaded

settings = LazySettings()
