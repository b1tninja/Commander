#  _  __  
# | |/ /___ ___ _ __  ___ _ _ ®
# | ' </ -_) -_) '_ \/ -_) '_|
# |_|\_\___\___| .__/\___|_|
#              |_|            
#
# Keeper Commander 
# Contact: ops@keepersecurity.com
#
import base64
import enum
import json
import logging
import os
from typing import Optional
from urllib.parse import urlparse, urlunparse

LAST_RECORD_UID = 'last_record_uid'
LAST_SHARED_FOLDER_UID = 'last_shared_folder_uid'
LAST_FOLDER_UID = 'last_folder_uid'
LAST_TEAM_UID = 'last_team_uid'


class KeeperRegion(enum.Enum):
    COM = enum.auto()
    EU = enum.auto()


class RestApiContext:
    __REGION_SERVERS = {
        KeeperRegion.COM: 'keepersecurity.com',
        KeeperRegion.EU: 'keepersecurity.eu',
        # KeeperRegion.US: 'keepersecurity.us'
    }

    DEFAULT_REGION = KeeperRegion.COM

    def __init__(self, region=DEFAULT_REGION, locale='en_US', device_id=None, **kwargs):
        if region:
            if type(region) is str:
                region = region.upper()
                try:
                    region = KeeperRegion[region]
                except:
                    logging.warning(f"Unknown region '{region}' in configuration, using default instead.")
                    region = KeeperRegion.COM
            else:
                assert type(region) is KeeperRegion

        elif 'server' in kwargs and kwargs['server']:
            logging.debug("Update config.json region")
            p = urlparse(kwargs['server'])
            for server_region, server in self.__REGION_SERVERS.items():
                if server == p.netloc.lower():
                    region = server_region
                    break
            else:
                region = KeeperRegion.COM
                logging.warning(f"Unrecognized domain: {p.netloc} configured.")
        else:
            region = KeeperRegion.COM

        self.region = region
        self.transmission_key = None
        self.__server_key_id = 1
        self.locale = locale
        self.__device_id = device_id
        self.__store_server_key = False

    def __get_server_base(self):
        return urlunparse(('https', self.__REGION_SERVERS[self.region], '/api/rest/', None, None, None))

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

    server_base = property(__get_server_base)
    device_id = property(__get_device_id, __set_device_id)
    server_key_id = property(__get_server_key_id, __set_server_key_id)
    store_server_key = property(__get_store_server_key)


class KeeperParams:
    """ Global storage of data during the session """

    def __init__(self, config_filename='', *,
                 user: str = '',
                 server: Optional[str] = None,
                 region: Optional[str] = None,
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

        # config.update(locals())

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

        if not mfa_type:
            mfa_type = 'device_token'

        device_id = base64.urlsafe_b64decode(device_id + '==')

        rest_context = RestApiContext(region=region, server=server, device_id=device_id)
        server = rest_context.server_base

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
        self.device_id = device_id
        self.__rest_context = rest_context
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
            if os.path.exists(config_filename):
                with open(config_filename) as config_file:
                    config = json.load(config_file)
        except IOError as ioe:
            logging.warning('Error: Unable to open config file %s: %s.', config_filename, ioe)
        except Exception as e:
            logging.error(
                'Unable to parse JSON configuration file "%s". Please check config for errors.',
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

    def __get_region(self):
        return self.rest_context.region.name

    def __get_url(self):
        url = urlparse(self.__server)
        return urlunparse((url.scheme, url.netloc, '/', None, None, None))

    def __get_domain(self):
        url = urlparse(self.__server)
        return url.netloc

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

    region = property(__get_server)
    domain = property(__get_domain)
    url = property(__get_url)
    server = property(__get_server, __set_server)
    rest_context = property(__get_rest_context)
