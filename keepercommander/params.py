#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#
import os
import json
import base64
import logging
from urllib.parse import urlparse, urlunparse

LAST_RECORD_UID = 'last_record_uid'
LAST_SHARED_FOLDER_UID = 'last_shared_folder_uid'
LAST_FOLDER_UID = 'last_folder_uid'
LAST_TEAM_UID = 'last_team_uid'


class RestApiContext:
    def __init__(self, server='https://keepersecurity.com/api/v2/', locale='en_US', device_id=None):
        self.server_base = server
        self.transmission_key = None
        self.__server_key_id = 1
        self.locale = locale
        self.__device_id = device_id
        self.__store_server_key = False

    def __get_server_base(self):
        return self.__server_base

    def __set_server_base(self, value):
        p = urlparse(value)
        self.__server_base = urlunparse((p.scheme, p.netloc, '/api/rest/', None, None, None))

    def __get_server_key_id(self):
        return self.__server_key_id

    def __set_server_key_id(self, key_id):
        self.__server_key_id = key_id
        self.__store_server_key = True

    def __get_device_id(self):
        return self.__device_id

    def __set_device_id(self, device_id):
        self.__device_id = device_id
        self.__store_server_key = True

    def __get_store_server_key(self):
        return self.__store_server_key

    server_base = property(__get_server_base, __set_server_base)
    device_id = property(__get_device_id, __set_device_id)
    server_key_id = property(__get_server_key_id, __set_server_key_id)
    store_server_key = property(__get_store_server_key)


import enum


class MfaType(enum.Enum):
    device_token = 1


class KeeperParams:
    """ Global storage of data during the session """
    DEFAULT_ENDPOINT = 'https://keepersecurity.com/api/v2/'

    def __init__(self, config_filename='', *,
                 user: str = '',
                 server: str = DEFAULT_ENDPOINT,
                 password: str = '',
                 timedelay: int = 0,
                 mfa_token: str = '',
                 mfa_type: str = '',  # device_token
                 commands: list = None,
                 plugins: list = None,
                 debug: bool = False,
                 batch_mode: bool = False,
                 device_id: str = '',
                 logout_timer=0,
                 login_v3: bool = True,
                 private_key: str = '',
                 **config):

        if commands is None:
            commands = []
        else:
            assert type(commands) is list
            assert all([type(cmd) is dict for cmd in commands])

        if plugins is None:
            plugins = list()
        else:
            assert type(plugins) is list
            assert all([type(plugin) is dict for plugin in plugins])

        if debug:
            debug = True
            logging.getLogger().setLevel(logging.DEBUG)
            logging.debug('Debug ON')

        self.config_filename = config_filename
        self.config = config
        self.auth_verifier = None
        self.__server = server
        self.user = user.lower()
        self.password = password
        self.mfa_token = mfa_token
        self.mfa_type = mfa_type or 'device_token'
        self.commands = []
        self.plugins = []
        self.session_token = None
        self.salt = None
        self.iterations = 0
        self.data_key = None
        self.rsa_key = None
        self.revision = 0
        self.record_cache = {}
        self.meta_data_cache = {}
        self.shared_folder_cache = {}
        self.team_cache = {}
        self.key_cache = {}  # team or user
        self.available_team_cache = None
        self.subfolder_cache = {}
        self.subfolder_record_cache = {}
        self.non_shared_data_cache = {}
        self.root_folder = None
        self.current_folder = None
        self.folder_cache = {}
        self.debug = False
        self.timedelay = timedelay
        self.sync_data = True
        self.license = None
        self.settings = None
        self.enforcements = None
        self.enterprise = None
        self.enterprise_id = 0
        self.msp_tree_key = None
        self.prepare_commands = False
        self.batch_mode = batch_mode
        device_id = base64.urlsafe_b64decode(device_id + '==')
        self.device_id = device_id
        self.__rest_context = RestApiContext(server=server, device_id=device_id)
        self.pending_share_requests = set()
        self.environment_variables = {}
        self.record_history = {}  # type: dict[str, (list[dict], int)]
        self.event_queue = []
        self.logout_timer = logout_timer
        self.login_v3 = login_v3
        self.clone_code = None
        self.device_token = None
        self.device_private_key = private_key

    @classmethod
    def from_config(cls, config_filename):
        config_filename = os.getenv('KEEPER_CONFIG_FILE', config_filename or 'config.json')

        config = {}
        try:
            with open(config_filename) as config_file:
                config = json.load(config_file)
        except IOError as ioe:
            logging.warning('Error: Unable to open config file %s: %s.', config_filename, ioe)
        except Exception as e:
            logging.error('Unable to parse JSON configuration file "%s". Please check config for errors, and ensure the directory and config are writable.',
                config_filename)
        else:
            logging.debug(f'Parsed config JSON successfully: {config_filename}.')
            return cls(config_filename=config_filename, **config)


    def clear_session(self):
        self.auth_verifier = ''
        self.user = ''
        self.password = ''
        self.mfa_type = 'device_token'
        self.mfa_token = ''
        self.commands.clear()
        self.session_token = None
        self.salt = None
        self.iterations = 0
        self.data_key = None
        self.rsa_key = None
        self.revision = 0
        self.record_cache.clear()
        self.meta_data_cache.clear()
        self.shared_folder_cache.clear()
        self.team_cache.clear()
        self.available_team_cache = None
        self.key_cache.clear()
        self.subfolder_cache.clear()
        self.subfolder_record_cache.clear()
        self.non_shared_data_cache.clear()
        if self.folder_cache:
            self.folder_cache.clear()

        self.root_folder = None
        self.current_folder = None
        self.sync_data = True
        self.license = None
        self.settings = None
        self.enforcements = None
        self.enterprise = None
        self.enterprise_id = 0
        self.msp_tree_key = None
        self.prepare_commands = True
        self.batch_mode = False
        self.pending_share_requests.clear()
        self.environment_variables.clear()
        self.record_history.clear()
        self.event_queue.clear()
        self.logout_timer = self.config.get('logout_timer') or 0
        # self.login_v3 = self.config.get('login_v3') or True
        self.clone_code = None
        self.device_token = None
        self.device_private_key = None

    def __get_rest_context(self):
        return self.__rest_context

    def __get_server(self):
        return self.__server

    def __set_server(self, value):
        self.__server = value
        self.__rest_context.server_base = value

    def queue_audit_event(self, name, **kwargs):
        # type: (str, dict) -> None
        if self.license and 'account_type' in self.license:
            if self.license['account_type'] == 2:
                self.event_queue.append({
                    'audit_event_type': name,
                    'inputs': {x: kwargs[x] for x in kwargs if
                               x in {'record_uid', 'file_format', 'attachment_id', 'to_username'}}
                })

    server = property(__get_server, __set_server)
    rest_context = property(__get_rest_context)
