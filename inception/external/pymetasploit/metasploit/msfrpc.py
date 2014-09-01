#!/usr/bin/env python3

from http.client import HTTPConnection, HTTPSConnection
from numbers import Number

from msgpack import packb, unpackb

from inception.external.pymetasploit.metasploit.utils import convert

__author__ = 'Nadeem Douba'
__copyright__ = 'Copyright 2012, PyMetasploit Project'
__credits__ = []

__license__ = 'GPL'
__version__ = '0.4'
__maintainer__ = 'Nadeem Douba'
__email__ = 'ndouba@gmail.com'
__status__ = 'Development'

__all__ = [
    'MsfRpcError',
    'MsfRpcMethod',
    'MsfPlugins',
    'MsfRpcClient',
    'MsfTable',
    'NotesTable',
    'LootsTable',
    'CredsTable',
    'AuthInfoTable',
    'HostsTable',
    'ServicesTable',
    'VulnsTable',
    'EventsTable',
    'ClientsTable',
    'Workspace',
    'MsfManager',
    'WorkspaceManager',
    'DbManager',
    'AuthManager',
    'PluginManager',
    'JobManager',
    'CoreManager',
    'MsfModule',
    'ExploitModule',
    'PostModule',
    'EncoderModule',
    'AuxiliaryModule',
    'PayloadModule',
    'NopModule',
    'ModuleManager',
    'MsfSession',
    'MeterpreterSession',
    'ShellSession',
    'SessionManager',
    'MsfConsole',
    'ConsoleManager',
    'ReportFilter',
    'ReportFilterQuery'
]


class MsfRpcError(Exception):
    pass


class MsfRpcMethod(object):
    AuthLogin = 'auth.login'
    AuthLogout = 'auth.logout'
    AuthTokenList = 'auth.token_list'
    AuthTokenAdd = 'auth.token_add'
    AuthTokenGenerate = 'auth.token_generate'
    AuthTokenRemove = 'auth.token_remove'
    ConsoleCreate = 'console.create'
    ConsoleList = 'console.list'
    ConsoleDestroy = 'console.destroy'
    ConsoleRead = 'console.read'
    ConsoleWrite = 'console.write'
    ConsoleTabs = 'console.tabs'
    ConsoleSessionKill = 'console.session_kill'
    ConsoleSessionDetach = 'console.session_detach'
    CoreVersion = 'core.version'
    CoreStop = 'core.stop'
    CoreSetG = 'core.setg'
    CoreUnsetG = 'core.unsetg'
    CoreSave = 'core.save'
    CoreReloadModules = 'core.reload_modules'
    CoreModuleStats = 'core.module_stats'
    CoreAddModulePath = 'core.add_module_path'
    CoreThreadList = 'core.thread_list'
    CoreThreadKill = 'core.thread_kill'
    DbHosts = 'db.hosts'
    DbServices = 'db.services'
    DbVulns = 'db.vulns'
    DbWorkspaces = 'db.workspaces'
    DbCurrentWorkspace = 'db.current_workspace'
    DbGetWorkspace = 'db.get_workspace'
    DbSetWorkspace = 'db.set_workspace'
    DbDelWorkspace = 'db.del_workspace'
    DbAddWorkspace = 'db.add_workspace'
    DbGetHost = 'db.get_host'
    DbReportHost = 'db.report_host'
    DbReportService = 'db.report_service'
    DbGetService = 'db.get_service'
    DbGetNote = 'db.get_note'
    DbGetClient = 'db.get_client'
    DbReportClient = 'db.report_client'
    DbReportNote = 'db.report_note'
    DbNotes = 'db.notes'
    DbReportAuthInfo = 'db.report_auth_info'
    DbGetAuthInfo = 'db.get_auth_info'
    DbGetRef = 'db.get_ref'
    DbDelVuln = 'db.del_vuln'
    DbDelNote = 'db.del_note'
    DbDelService = 'db.del_service'
    DbDelHost = 'db.del_host'
    DbReportVuln = 'db.report_vuln'
    DbEvents = 'db.events'
    DbReportEvent = 'db.report_event'
    DbReportLoot = 'db.report_loot'
    DbLoots = 'db.loots'
    DbReportCred = 'db.report_cred'
    DbCreds = 'db.creds'
    DbImportData = 'db.import_data'
    DbGetVuln = 'db.get_vuln'
    DbClients = 'db.clients'
    DbDelClient = 'db.del_client'
    DbDriver = 'db.driver'
    DbConnect = 'db.connect'
    DbStatus = 'db.status'
    DbDisconnect = 'db.disconnect'
    JobList = 'job.list'
    JobStop = 'job.stop'
    JobInfo = 'job.info'
    ModuleExploits = 'module.exploits'
    ModuleAuxiliary = 'module.auxiliary'
    ModulePayloads = 'module.payloads'
    ModuleEncoders = 'module.encoders'
    ModuleNops = 'module.nops'
    ModulePost = 'module.post'
    ModuleInfo = 'module.info'
    ModuleCompatiblePayloads = 'module.compatible_payloads'
    ModuleCompatibleSessions = 'module.compatible_sessions'
    ModuleTargetCompatiblePayloads = 'module.target_compatible_payloads'
    ModuleOptions = 'module.options'
    ModuleExecute = 'module.execute'
    ModuleEncodeFormats = 'module.encode_formats'
    ModuleEncode = 'module.encode'
    PluginLoad = 'plugin.load'
    PluginUnload = 'plugin.unload'
    PluginLoaded = 'plugin.loaded'
    SessionList = 'session.list'
    SessionStop = 'session.stop'
    SessionShellRead = 'session.shell_read'
    SessionShellWrite = 'session.shell_write'
    SessionShellUpgrade = 'session.shell_upgrade'
    SessionMeterpreterRead = 'session.meterpreter_read'
    SessionRingRead = 'session.ring_read'
    SessionRingPut = 'session.ring_put'
    SessionRingLast = 'session.ring_last'
    SessionRingClear = 'session.ring_clear'
    SessionMeterpreterWrite = 'session.meterpreter_write'
    SessionMeterpreterSessionDetach = 'session.meterpreter_session_detach'
    SessionMeterpreterSessionKill = 'session.meterpreter_session_kill'
    SessionMeterpreterTabs = 'session.meterpreter_tabs'
    SessionMeterpreterRunSingle = 'session.meterpreter_run_single'
    SessionMeterpreterScript = 'session.meterpreter_script'
    SessionMeterpreterDirectorySeparator = 'session.meterpreter_directory_separator'
    SessionCompatibleModules = 'session.compatible_modules'


class MsfPlugins(object):
    IpsFilter = "ips_filter"
    SocketLogger = "socket_logger"
    DbTracker = "db_tracker"
    Sounds = "sounds"
    AutoAddRoute = "auto_add_route"
    DbCredCollect = "db_credcollect"


class MsfRpcClient(object):

    _headers = {
        'Content-Type' : 'binary/message-pack'
    }

    def __init__(self, password, **kwargs):
        """
        Connects and authenticates to a Metasploit RPC daemon.

        Mandatory Arguments:
        - password : the password used to authenticate to msfrpcd

        Optional Keyword Arguments:
        - username : the username used to authenticate to msfrpcd (default: msf)
        - uri : the msfrpcd URI (default: /api/)
        - port : the remote msfrpcd port to connect to (default: 55553)
        - server : the remote server IP address hosting msfrpcd (default: localhost)
        - ssl : if true uses SSL else regular HTTP (default: SSL enabled)
        """
        self.uri = kwargs.get('uri', '/api/')
        self.port = kwargs.get('port', 55553)
        self.server = kwargs.get('server', '127.0.0.1')
        self.ssl = kwargs.get('ssl', True)
        self.sessionid = kwargs.get('token')
        if self.ssl:
            self.client = HTTPSConnection(self.server, self.port)
        else:
            self.client = HTTPConnection(self.server, self.port)
        self.login(kwargs.get('username', 'msf'), password)

    def call(self, method, *args):
        """
        Builds an RPC request and retrieves the result.

        Mandatory Arguments:
        - method : the RPC call method name (e.g. db.clients)

        Optional Arguments:
        - *args : the RPC method's parameters if necessary

        Returns : RPC call result
        """
        l = [ method ]
        l.extend(args)
        if method == MsfRpcMethod.AuthLogin:
            self.client.request('POST', self.uri, packb(l), self._headers)
            r = self.client.getresponse()
            if r.status == 200:
                return convert(unpackb(r.read()))
            raise MsfRpcError('An unknown error has occurred while logging in.')
        elif self.authenticated:
            l.insert(1, self.sessionid)
            self.client.request('POST', self.uri, packb(l), self._headers)
            r = self.client.getresponse()
            if r.status == 200:
                result = convert(unpackb(r.read()))
                if 'error' in result:
                    raise MsfRpcError(result['error_message'])
                return result
            raise MsfRpcError('An unknown error has occurred while performing the RPC call.')
        raise MsfRpcError('You cannot perform this call because you are not authenticated.')

    @property
    def core(self):
        """
        The msf RPC core manager.
        """
        return CoreManager(self)

    @property
    def modules(self):
        """
        The msf RPC modules RPC manager.
        """
        return ModuleManager(self)

    @property
    def sessions(self):
        """
        The msf RPC sessions (meterpreter & shell) manager.
        """
        return SessionManager(self)

    @property
    def jobs(self):
        """
        The msf RPC jobs manager.
        """
        return JobManager(self)

    @property
    def consoles(self):
        """
        The msf RPC consoles manager
        """
        return ConsoleManager(self)

    @property
    def authenticated(self):
        """
        Whether or not this client is authenticated.
        """
        return self.sessionid is not None

    @property
    def plugins(self):
        """
        The msf RPC plugins manager.
        """
        return PluginManager(self)

    @property
    def db(self):
        """
        The msf RPC database manager.
        """
        return DbManager(self)

    @property
    def auth(self):
        """
        The msf authentication manager.
        """
        return AuthManager(self)

    def login(self, username, password):
        """
        Authenticates and reauthenticates the user to msfrpcd.
        """
        if self.sessionid is None:
            r = self.call(MsfRpcMethod.AuthLogin, username, password)
            try:
                if r['result'] == 'success':
                    self.sessionid = r['token']
            except KeyError:
                raise MsfRpcError('Login failed.')
        else:
            try:
                r = self.call(MsfRpcMethod.DbStatus)
            except MsfRpcError:
                raise MsfRpcError('Login failed.')

    def logout(self):
        """
        Logs the current user out. Note: do not call directly.
        """
        self.call(MsfRpcMethod.AuthLogout, self.sessionid)


class MsfTable(object):

    def __init__(self, rpc, wname):
        self.rpc = rpc
        self.name = wname

    def dbreport(self, atype, attrs):
        attrs.update({ 'workspace' : self.name })
        return self.rpc.call('db.report_%s' % atype, attrs)

    def dbdel(self, atype, attrs):
        attrs.update({ 'workspace' : self.name })
        return self.rpc.call('db.del_%s' % atype, attrs)

    def dbget(self, atype, attrs):
        attrs.update({ 'workspace' : self.name })
        return self.rpc.call('db.get_%s' % atype, attrs)[atype]

    def records(self, atypes, **kwargs):
        kwargs.update({'workspace' : self.name})
        return self.rpc.call('db.%s' % atypes, kwargs)[atypes]

    @property
    def list(self):
        raise NotImplementedError

    def report(self, *args, **kwargs):
        raise NotImplementedError

    def delete(self, *args, **kwargs):
        raise NotImplementedError

    def find(self, **kwargs):
        raise NotImplementedError

    update = report


class NotesTable(MsfTable):

    @property
    def list(self):
        return super(NotesTable, self).records('notes')

    def find(self, **kwargs):
        """
        Find notes based on search criteria.

        Optional Keyword Arguments:
        - limit : the maximum number of results.
        - offset : skip n results.
        - addresses : a list of addresses to search for.
        - names : comma separated string of service names.
        - ntype : the note type.
        - ports : the port associated with the note.
        - proto : the protocol associated with the note.
        """
        if 'ports' in kwargs:
            kwargs['port'] = True
        return super(NotesTable, self).records('notes', **kwargs)

    def report(self, type, data, **kwargs):
        """
        Report a Note to the database.  Notes can be tied to a Workspace, Host, or Service.

        Mandatory Arguments:
        - type : The type of note, e.g. 'smb_peer_os'.
        - data : whatever it is you're making a note of.

        Optional Keyword Arguments:
        - host : an IP address or a Host object to associate with this Note.
        - service : a dict containing 'host', 'port', 'proto' and optionally 'name' keys.
        - port : along with 'host' and 'proto', a service to associate with this Note.
        - proto : along with 'host' and 'port', a service to associate with this Note.
        - update : what to do in case a similar Note exists, see below.

        The 'update' option can have the following values:
        - unique : allow only a single Note per host/type pair.
        - unique_data : like 'unique', but also compare 'data'.
        - insert : always insert a new Note even if one with identical values exists.

        If the provided 'host' is an IP address and does not exist in the database,
        it will be created. If 'host' and 'service' are all omitted, the new Note
        will be associated with the current 'workspace'.
        """
        kwargs.update({ 'data' : data, 'type' : type })
        kwargs.update(kwargs.pop('service', {}))
        self.dbreport('note', kwargs)

    def delete(self, **kwargs):
        """
        Delete one or more notes based on a search criteria.

        Optional Keyword Arguments:
        - host : the host associated with a Note, not required if 'address' or 'addresses' is specified
        - address : the address associated with a Note, not required if 'host' or 'addresses' is specified.
        - addresses : a list of addresses associated with Notes, not required if 'host' or 'address' is specified.
        - port : the port associated with a Note.
        - proto : the protocol associated with a Note.
        - ntype : the note type, e.g. 'smb_peer_os'.
        """
        self.dbdel('note', kwargs)

    def get(self, **kwargs):
        """
        Get a Note from the database based on the specifications of one or more keyword arguments.

        Mandatory Keyword Arguments:
        - host : the host associated with a Note, not required if 'address' or 'addr' is specified.
        - address : the address associated with a Note, not required if 'host' or 'addr' is specified.
        - addr : same as 'address', not required if 'host' or 'address' is specified.

        Optional Keyword Arguments:
        - proto : the protocol associated with the Note.
        - port : the port associated with the Note.
        - ntype : the type of Note.
        """
        if not any([i in kwargs for i in ('host', 'address', 'addr')]):
            raise TypeError('Expected a host, address, or addr.')
        return self.dbget('note', kwargs)

    update = report


class LootsTable(MsfTable):

    @property
    def list(self):
        return super(LootsTable, self).records('loots')

    def find(self, **kwargs):
        """
        Find loot based on search criteria.

        Optional Keyword Arguments:
        - limit : the maximum number of results.
        - offset : skip n results.
        """
        return super(LootsTable, self).records('loots', **kwargs)

    def report(self, path, type, **kwargs):
        """
        Report Loot to the database

        Mandatory Arguments:
        - path : the filesystem path to the Loot
        - type : the type of Loot
        - ltype : the same as 'type', not required if 'type' is specified.

        Optional Keyword Arguments:
        - host : an IP address or a Host object to associate with this Note
        - ctype : the content type of the loot, e.g. 'text/plain'
        - content_type : same as 'ctype'.
        - service : a service to associate Loot with.
        - name : a name to associate with this Loot.
        - info : additional information about this Loot.
        - data : the data within the Loot.
        """
        kwargs.update({ 'path' : path, 'type' : type })
        self.dbreport('loot', kwargs)

    update = report


class CredsTable(MsfTable):

    @property
    def list(self):
        return super(CredsTable, self).records('creds')

    def find(self, **kwargs):
        """
        Find creds based on search criteria.

        Optional Keyword Arguments:
        - limit : the maximum number of results.
        - offset : skip n results.
        """
        return super(CredsTable, self).records('creds', **kwargs)

    def report(self, host, port, **kwargs):
        """
        Store a set of credentials in the database.

        Mandatory Arguments:
        - host : an IP address or Host object reference
        - port : a port number

        Optional Keyword Arguments:
        - user : the username.
        - password : the password, or path to ssh_key.
        - ptype : the type of password (password(ish), hash, or ssh_key).
        - proto : a transport name for the port.
        - sname : service name.
        - active : by default, a cred is active, unless explicitly false.
        - proof : data used to prove the account is actually active.

        Sources: Credentials can be sourced from another credential, or from
        a vulnerability. For example, if an exploit was used to dump the
        smb_hashes, and this credential comes from there, the source_id would
        be the Vuln id (as reported by report_vuln) and the type would be "Vuln".

        - source_id : The Vuln or Cred id of the source of this cred.
        - source_type : Either Vuln or Cred.
        """
        kwargs.update({'host' : host, 'port' : port})
        kwargs['pass'] = kwargs.get('password')
        self.dbreport('cred', kwargs)

    update = report


class AuthInfoTable(MsfTable):

    def report(self, host, port, **kwargs):
        """
        Store a set of credentials in the database.

        Mandatory Arguments:
        - host : an IP address or Host object reference
        - port : a port number

        Optional Keyword Arguments:
        - user : the username.
        - pass : the password, or path to ssh_key.
        - ptype : the type of password (password(ish), hash, or ssh_key).
        - proto : a transport name for the port.
        - sname : service name.
        - active : by default, a cred is active, unless explicitly false.
        - proof : data used to prove the account is actually active.

        Sources: Credentials can be sourced from another credential, or from
        a vulnerability. For example, if an exploit was used to dump the
        smb_hashes, and this credential comes from there, the source_id would
        be the Vuln id (as reported by report_vuln) and the type would be "Vuln".

        - source_id : The Vuln or Cred id of the source of this cred.
        - source_type : Either Vuln or Cred.
        """
        kwargs.update({'host' : host, 'port' : port})
        self.dbreport('auth_info', kwargs)

    update = report


class HostsTable(MsfTable):

    @property
    def list(self):
        return super(HostsTable, self).records('hosts')

    def find(self, **kwargs):
        """
        Find hosts based on search criteria.

        Optional Keyword Arguments:
        - limit : the maximum number of results.
        - offset : skip n results.
        - only_up : find only hosts that are alive.
        - addresses : find hosts based on a list of addresses.
        """
        return super(HostsTable, self).records('hosts', **kwargs)

    def report(self, host, **kwargs):
        """
        Store a host in the database.

        Mandatory Keyword Arguments:
        - host : an IP address or Host object reference.

        Optional Keyword Arguments:
        - state : a host state.
        - os_name : an operating system.
        - os_flavor : something like 'XP or 'Gentoo'.
        - os_sp : something like 'SP2'.
        - os_lang : something like 'English', 'French', or 'en-US'.
        - arch : an architecture.
        - mac : the host's MAC address.
        - scope : interface identifier for link-local IPv6.
        - virtual_host : the name of the VM host software, e.g. 'VMWare', 'QEMU', 'Xen', etc.
        """
        kwargs.update({'host' : host})
        self.dbreport('host', kwargs)

    def delete(self, **kwargs):
        """
        Deletes a host and associated data matching this address/comm.

        Mandatory Keyword Arguments:
        - host : the host associated with a Note, not required if 'address' or 'addresses' is specified
        - address : the address associated with a Note, not required if 'host' or 'addresses' is specified.
        - addresses : a list of addresses associated with Notes, not required if 'host' or 'address' is specified.
        """
        if not any([ i in kwargs for i in ('host', 'address', 'addresses')]):
            raise TypeError('Expected host, address, or addresses.')
        self.dbdel('host', kwargs)

    def get(self, **kwargs):
        """
        Get a host in the database.

        Mandatory Keyword Arguments:
        - host : the host associated with a Note, not required if 'address' or 'addr' is specified.
        - address : the address associated with a Note, not required if 'host' or 'addr' is specified.
        - addr : same as 'address', not required if 'host' or 'address' is specified.
        """
        if not any([ i in kwargs for i in ('addr', 'address', 'host')]):
            raise TypeError('Expected addr, address, or host.')
        return self.dbget('host', kwargs)

    update = report


class ServicesTable(MsfTable):

    @property
    def list(self):
        return super(ServicesTable, self).records('services')

    def find(self, **kwargs):
        """
        Find hosts based on search criteria.

        Optional Keyword Arguments:
        - limit : the maximum number of results.
        - offset : skip n results.
        - only_up : find only hosts that are alive.
        - addresses : find hosts based on a list of addresses.
        - proto : the protocol of the service.
        - ports : a comma separated string of ports.
        - names : a comma separated string of service names.
        """
        return super(ServicesTable, self).records('services', **kwargs)

    def report(self, host, port, proto, **kwargs):
        """
        Record a service in the database.

        Mandatory Arguments:
        - host : the host where this service is running.
        - port :  the port where this service listens.
        - proto : the transport layer protocol (e.g. tcp, udp).

        Optional Keyword Arguments:
        - name : the application layer protocol (e.g. ssh, mssql, smb)
        - sname : an alias for the above
        """
        kwargs.update({'host' : host, 'port' : port, 'proto' : proto})
        self.dbreport('service', kwargs)

    def delete(self, **kwargs):
        """
        Deletes a port and associated vulns matching this port.

        Mandatory Keyword Arguments:
        - host : the host associated with a Note, not required if 'address' or 'addresses' is specified
        - address : the address associated with a Note, not required if 'host' or 'addresses' is specified.
        - addresses : a list of addresses associated with Notes, not required if 'host' or 'address' is specified.

        or

        - port : used along with 'proto', specifies a service.
        - proto : used along with 'port', specifies a service.
        """
        if not any([i in kwargs for i in ('host', 'address', 'addresses')]) and \
           not all([i in kwargs for i in ('proto', 'port')]):
            raise TypeError('Expected host or port/proto pair.')
        self.dbdel('service', kwargs)

    def get(self, **kwargs):
        """
        Get a service record from the database.

        Mandatory Keyword Arguments:
        - host : the host associated with a Note, not required if 'address' or 'addresses' is specified
        - address : the address associated with a Note, not required if 'host' or 'addresses' is specified.
        - addresses : a list of addresses associated with Notes, not required if 'host' or 'address' is specified.

        or

        - port : used along with 'proto', specifies a service.
        - proto : used along with 'port', specifies a service.

        Optional Keyword Arguments:
        - up : specifies whether or not the service is alive.
        - names : a comma separated string of service names.
        """
        if not any([i in kwargs for i in ('host', 'addr', 'address')]) and \
           not all([i in kwargs for i in ('proto', 'port')]):
            raise TypeError('Expected host or port/proto pair.')
        return self.dbget('service', kwargs)

    update = report


class VulnsTable(MsfTable):

    @property
    def list(self):
        return super(VulnsTable, self).records('vulns')

    def find(self, **kwargs):
        """
        Find vulns based on search criteria.

        Optional Keyword Arguments:
        - limit : the maximum number of results.
        - offset : skip n results.
        - addresses : find hosts based on a list of addresses.
        - proto : the protocol of the service.
        - ports : a comma separated string of ports.
        - names : a comma separated string of service names.
        """
        return super(VulnsTable, self).records('vulns', **kwargs)

    def report(self, host, name, **kwargs):
        """
        Record a Vuln in the database.

        Mandatory Arguments:
        - host : the host where this vulnerability resides.
        - name : the scanner-specific id of the vuln (e.g. NEXPOSE-cifs-acct-password-never-expires).

        Optional Keyword Arguments:
        - info : a human readable description of the vuln, free-form text.
        - refs : an array of Ref objects or string names of references.
        """
        kwargs.update({'host' : host, 'name' : name})
        self.dbreport('vuln', kwargs)

    def delete(self, **kwargs):
        """
        Deletes a vuln and associated data matching this address/comm.

        Mandatory Keyword Arguments:
        - host : the host associated with a Note, not required if 'address' or 'addresses' is specified
        - address : the address associated with a Note, not required if 'host' or 'addresses' is specified.
        - addresses : a list of addresses associated with Notes, not required if 'host' or 'address' is specified.
        """
        if not any([ i in kwargs for i in ('host', 'address', 'addresses')]):
            raise TypeError('Expected host, address, or addresses.')
        self.dbdel('vuln', kwargs)

    def get(self, **kwargs):
        """
        Get a vuln in the database.

        Mandatory Keyword Arguments:
        - host : the host associated with a Note, not required if 'address' or 'addr' is specified.
        - address : the address associated with a Note, not required if 'host' or 'addr' is specified.
        - addr : same as 'address', not required if 'host' or 'address' is specified.
        """
        if not any([ i in kwargs for i in ('addr', 'address', 'host')]):
            raise TypeError('Expected addr, address, or host.')
        return self.dbreport('vuln', kwargs)

    update = report


class EventsTable(MsfTable):

    @property
    def list(self):
        return super(EventsTable, self).records('events')

    def find(self, **kwargs):
        """
        Find events based on search criteria.

        Optional Keyword Arguments:
        - limit : the maximum number of results.
        - offset : skip n results.
        """
        return super(EventsTable, self).records('events', **kwargs)

    def report(self, **kwargs):
        """
        Record a Vuln in the database.

        Mandatory Arguments:
        - username : user that invoked the event.
        - host : host that invoked the event.
        """
        if not any([i in kwargs for i in ('username', 'host')]):
            raise TypeError('Expected either username or host')
        self.dbreport('vuln', kwargs)

    update = report


class ClientsTable(MsfTable):

    @property
    def list(self):
        return super(ClientsTable, self).records('clients')

    def find(self, **kwargs):
        """
        Find clients based on search criteria.

        Optional Keyword Arguments:
        - limit : the maximum number of results.
        - offset : skip n results.
        - ua_name : a user-agent string.
        - ua_ver : the user-agent version.
        - addresses : a list of IP addresses.
        """
        return super(ClientsTable, self).records('clients', **kwargs)

    def report(self, ua_string, host, **kwargs):
        """
        Report a client running on a host.

        Mandatory Arguments:
        - ua_string : the value of the User-Agent header
        - host : the host where this client connected from, can be an ip address or a Host object

        Optional Keyword Arguments
        - ua_name : one of the user agent name constants
        - ua_ver : detected version of the given client
        - campaign : an id or Campaign object

        Returns a Client.
        """
        kwargs.update({'host' : host, 'ua_string' : ua_string})
        self.dbreport('client', kwargs)

    def delete(self, **kwargs):
        """
        Deletes a client and associated data matching this address/comm.

        Mandatory Keyword Arguments:
        - host : the host associated with a Note, not required if 'address' or 'addresses' is specified
        - address : the address associated with a Note, not required if 'host' or 'addresses' is specified.
        - addresses : a list of addresses associated with Notes, not required if 'host' or 'address' is specified.
        """
        self.dbdel('client', kwargs)

    def get(self, **kwargs):
        """
        Get a client in the database.

        Mandatory Keyword Arguments:
        - host : the host associated with a Note, not required if 'address' or 'addr' is specified.
        - ua_string : the value of the User-Agent header
        """
        if not any([ i in kwargs for i in ('host', 'ua_string')]):
            raise TypeError('Expected host or ua_string.')
        return self.dbreport('client', kwargs)

    update = report


class Workspace(object):

    def __init__(self, rpc, name):
        """
        Initializes a workspace object.

        Mandatory Arguments:
        - rpc : the msfrpc client object
        - name : the name of the workspace
        """
        self.rpc = rpc
        self.name = name

    @property
    def current(self):
        """
        The name of the current workspace.
        """
        return self.name

    @current.setter
    def current(self, name):
        self.name = name

    @property
    def notes(self):
        """
        Returns the notes table for the current workspace.
        """
        return NotesTable(self.rpc, self.name)

    @property
    def hosts(self):
        """
        Returns the hosts table for the current workspace.
        """
        return HostsTable(self.rpc, self.name)

    @property
    def services(self):
        """
        Returns the services table for the current workspace.
        """
        return ServicesTable(self.rpc, self.name)

    @property
    def vulns(self):
        """
        Returns the vulns table for the current workspace.
        """
        return VulnsTable(self.rpc, self.name)

    @property
    def events(self):
        """
        Returns the events table for the current workspace.
        """
        return EventsTable(self.rpc, self.name)

    @property
    def loots(self):
        """
        Returns the loots table for the current workspace.
        """
        return LootsTable(self.rpc, self.name)

    @property
    def creds(self):
        """
        Returns the creds table for the current workspace.
        """
        return CredsTable(self.rpc, self.name)

    @property
    def clients(self):
        """
        Returns the clients table for the current workspace.
        """
        return ClientsTable(self.rpc, self.name)

    def delete(self):
        """
        Delete the current workspace.
        """
        self.rpc.call(MsfRpcMethod.DbDelWorkspace, {'workspace' : self.name})

    def importdata(self, data):
        self.rpc.call(MsfRpcMethod.DbImportData, {'workspace' : self.name, 'data' : data})

    def importfile(self, fname):
        r = file(fname, mode='rb')
        self.rpc.call(MsfRpcMethod.DbImportData, {'workspace' : self.name, 'data' : r.read()})
        r.close()


class MsfManager(object):

    def __init__(self, rpc):
        """
        Initialize a msf component manager.

        Mandatory Arguments:
        - rpc : the msfrpc client object.
        """
        self.rpc = rpc


class WorkspaceManager(MsfManager):

    @property
    def list(self):
        """
        The list of all workspaces in the current msf database.
        """
        return self.rpc.call(MsfRpcMethod.DbWorkspaces)['workspaces']

    def workspace(self, name='default'):
        """
        Returns a Workspace object for the given workspace name.

        Optional Arguments:
        - name : the name of the workspace
        """
        w = self.list
        if name not in w:
            self.add(name)
        return Workspace(self.rpc, name)

    def add(self, name):
        """
        Adds a workspace with the given name.

        Mandatory Arguments:
        - name : the name of the workspace
        """
        self.rpc.call(MsfRpcMethod.DbAddWorkspace, name)

    def get(self, name):
        """
        Get a workspace with the given name.

        Mandatory Arguments:
        - name : the name of the workspace
        """
        return self.rpc.call(MsfRpcMethod.DbGetWorkspace, name)['workspace']

    def remove(self, name):
        """
        Adds a workspace with the given name.

        Mandatory Arguments:
        - name : the name of the workspace
        """
        self.rpc.call(MsfRpcMethod.DbDelWorkspace, name)

    def set(self, name):
        """
        Sets the current workspace.

        Mandatory Arguments:
        - name : the name of the workspace
        """
        self.rpc.call(MsfRpcMethod.DbSetWorkspace, name)

    @property
    def current(self):
        """
        The current workspace.
        """
        return self.workspace(self.rpc.call(MsfRpcMethod.DbCurrentWorkspace)['workspace'])


class DbManager(MsfManager):

    def connect(self, username, database='msf', **kwargs):
        """
        Connects to a database and creates the msf schema if necessary.

        Mandatory Arguments:
        - username : the username for the database connection

        Optional Keyword Arguments:
        - host : the IP or hostname of the database server (default: 'localhost')
        - driver : the driver to use for the database connection (default: 'postgresql')
        - password : the password for the database connection
        - database : the database name (default: 'msf')
        - port : the port that the server is running on (default: 5432)
        """
        runopts = { 'username': username, 'database' : database }
        runopts.update(kwargs)
        return self.rpc.call(MsfRpcMethod.DbConnect, runopts)['result'] == 'success'

    @property
    def driver(self):
        """
        The current database driver in use.
        """
        return self.rpc.call(MsfRpcMethod.DbDriver, {})['driver']

    @driver.setter
    def driver(self, d):
        self.rpc.call(MsfRpcMethod.DbDriver, {'driver' : d})

    @property
    def status(self):
        """
        The status of the database connection.
        """
        return self.rpc.call(MsfRpcMethod.DbStatus)

    def disconnect(self):
        """
        Disconnect from the database.
        """
        self.rpc.call(MsfRpcMethod.DbDisconnect)

    @property
    def workspaces(self):
        """
        A WorkspaceManager object.
        """
        return WorkspaceManager(self.rpc)

    @property
    def workspace(self):
        """
        The name of the current workspace.
        """
        return self.rpc.call(MsfRpcMethod.DbCurrentWorkspace)['workspace']

    @workspace.setter
    def workspace(self, w):
        self.rpc.call(MsfRpcMethod.DbSetWorkspace, w)


class AuthManager(MsfManager):

    def login(self, password, **kwargs):
        """
        Login to the msfrpc daemon.

        Mandatory Arguments:
        - password : the password used to login to msfrpc

        Optional Keyword Arguments:
        - username : the username used to authenticate to msfrpcd (default: msf)
        - uri : the msfrpcd URI (default: /api/)
        - port : the remote msfrpcd port to connect to (default: 55553)
        - server : the remote server IP address hosting msfrpcd (default: localhost)
        - ssl : if true uses SSL else regular HTTP (default: SSL enabled)
        """
        return MsfRpcClient(password, **kwargs)

    def logout(self, sid):
        """
        Logs out a user for a given session ID.

        Mandatory Arguments:
        - sid : a session ID that is active.
        """
        return self.rpc.call(MsfRpcMethod.AuthLogout, sid)

    @property
    def tokens(self):
        """
        The current list of active session IDs.
        """
        return self.rpc.call(MsfRpcMethod.AuthTokenList)['tokens']

    def add(self, token):
        """
        Add a session ID or token.

        Mandatory Argument:
        - token : a random string used as a session identifier.
        """
        self.rpc.call(MsfRpcMethod.AuthTokenAdd, token)

    def remove(self, token):
        """
        Remove a session ID or token.

        Mandatory Argument:
        - token : a session ID or token that is active.
        """
        self.rpc.call(MsfRpcMethod.AuthTokenRemove, token)

    def generate(self):
        """
        Generate a session ID or token.
        """
        return self.rpc.call(MsfRpcMethod.AuthTokenGenerate)['token']


class PluginManager(MsfManager):

    @property
    def list(self):
        """
        A list of loaded plugins.
        """
        return self.rpc.call(MsfRpcMethod.PluginLoaded)['plugins']

    def load(self, plugin):
        """
        Load a plugin of a given name.

        Mandatory Arguments:
        - plugin : a name of a plugin to load.
        """
        self.rpc.call(MsfRpcMethod, MsfRpcMethod.PluginLoad, plugin)

    def unload(self, plugin):
        """
        Unload a plugin of a given name.

        Mandatory Arguments:
        - plugin : a name of a loaded plugin to unload.
        """
        self.rpc.call(MsfRpcMethod, MsfRpcMethod.PluginUnload, plugin)


class JobManager(MsfManager):

    @property
    def list(self):
        """
        A list of currently running jobs.
        """
        return self.rpc.call(MsfRpcMethod.JobList)

    def stop(self, jobid):
        """
        Stop a job.

        Mandatory Argument:
        - jobid : the ID of the job.
        """
        self.rpc.call(MsfRpcMethod.JobStop, jobid)

    def info(self, jobid):
        """
        Get job information for a particular job.

        Mandatory Argument:
        - jobid : the ID of the job.
        """
        return self.rpc.call(MsfRpcMethod.JobInfo, jobid)


class CoreManager(MsfManager):

    @property
    def version(self):
        """
        The version of msf core.
        """
        return self.rpc.call(MsfRpcMethod.CoreVersion)

    def stop(self):
        """
        Stop the core.
        """
        self.rpc.call(MsfRpcMethod.CoreStop)

    def setg(self, var, val):
        """
        Set a global variable

        Mandatory Arguments:
        - var : the variable name
        - val : the variable value
        """
        self.rpc.call(MsfRpcMethod.CoreSetG, var, val)

    def unsetg(self, var):
        """
        Unset a global variable

        Mandatory Arguments:
        - var : the variable name
        """
        self.rpc.call(MsfRpcMethod.CoreUnsetG, var)

    def save(self):
        """
        Save the core state.
        """
        self.rpc.call(MsfRpcMethod.CoreSave)

    def reload(self):
        """
        Reload all modules in the core.
        """
        self.rpc.call(MsfRpcMethod.CoreReloadModules)

    @property
    def stats(self):
        """
        Get module statistics from the core.
        """
        return self.rpc.call(MsfRpcMethod.CoreModuleStats)

    def addmodulepath(self, path):
        """
        Add a search path for additional modules.

        Mandatory Arguments:
        - path : the path to search for modules.
        """
        return self.rpc.call(MsfRpcMethod.CoreAddModulePath, path)

    @property
    def threads(self):
        """
        The current threads running in the core.
        """
        return self.rpc.call(MsfRpcMethod.CoreThreadList)

    def kill(self, threadid):
        """
        Kill a thread running in the core.

        Mandatory Arguments:
        - threadid : the thread ID.
        """
        self.rpc.call(MsfRpcMethod.CoreThreadKill, threadid)


class MsfModule(object):

    def __init__(self, rpc, mtype, mname):
        """
        Initializes an msf module object.

        Mandatory Arguments:
        - rpc : the msfrpc client object.
        - mtype : the module type (e.g. 'exploit')
        - mname : the module name (e.g. 'exploits/windows/http/icecast_header')
        """
        self.moduletype = mtype
        self.modulename = mname
        self.rpc = rpc
        self._info = rpc.call(MsfRpcMethod.ModuleInfo, mtype, mname)
        for k in self._info:
            setattr(self, k, self._info.get(k))
        self._moptions = rpc.call(MsfRpcMethod.ModuleOptions, mtype, mname)
        self._roptions = []
        self._aoptions = []
        self._eoptions = []
        self._runopts = {}
        for o in self._moptions:
            if self._moptions[o]['required']:
                self._roptions.append(o)
            if self._moptions[o]['advanced']:
                self._aoptions.append(o)
            if self._moptions[o]['evasion']:
                self._eoptions.append(o)
            if 'default' in self._moptions[o]:
                self._runopts[o] = self._moptions[o]['default']

    @property
    def options(self):
        """
        All the module options.
        """
        return list(self._moptions.keys())

    @property
    def required(self):
        """
        The required module options.
        """
        return self._roptions

    @property
    def evasion(self):
        """
        Module options that are used for evasion.
        """
        return self._eoptions

    @property
    def advanced(self):
        """
        Advanced module options.
        """
        return self._aoptions

    @property
    def runoptions(self):
        """
        The running (currently set) options for a module. This will raise an error
        if some of the required options are missing.
        """
        outstanding = set(self.required).difference(list(self._runopts.keys()))
        if outstanding:
            raise TypeError('Module missing required parameter: %s' % ', '.join(outstanding))
        return self._runopts

    def optioninfo(self, option):
        """
        Get information about the module option

        Mandatory Argument:
        - option : the option name.
        """
        return self._moptions[option]

    def __getitem__(self, item):
        """
        Get the current option value.

        Mandatory Arguments:
        - item : the option name.
        """
        if item not in self._moptions:
            raise KeyError("Invalid option '%s'." % item)
        return self._runopts.get(item)

    def __setitem__(self, key, value):
        """
        Set the current option value.

        Mandatory Arguments:
        - key : the option name.
        - value : the option value.
        """
        if key not in self.options:
            raise KeyError("Invalid option '%s'." % key)
        elif 'enums' in self._moptions[key] and value not in self._moptions[key]['enums']:
            raise ValueError("Value ('%s') is not one of %s" % (value, repr(self._moptions[key]['enums'])))
        elif self._moptions[key]['type'] == 'bool' and not isinstance(value, bool):
            raise TypeError("Value must be a boolean not '%s'" % type(value).__name__)
        elif self._moptions[key]['type'] in ['integer', 'float'] and not isinstance(value, Number):
            raise TypeError("Value must be an integer not '%s'" % type(value).__name__)
        self._runopts[key] = value

    def __delitem__(self, key):
        del self._runopts[key]

    def __contains__(self, item):
        return item in self._runopts

    def update(self, d):
        """
        Update a set of options.

        Mandatory Arguments:
        - d : a dictionary of options
        """
        for k in d:
            self[k] = d[k]

    def execute(self, **kwargs):
        """
        Executes the module with its run options as parameters.

        Optional Keyword Arguments:
        - payload : the payload of an exploit module (this is mandatory if the module is an exploit).
        - **kwargs : can contain any module options.
        """
        runopts = self.runoptions.copy()
        if isinstance(self, ExploitModule):
            payload = kwargs.get('payload')
            runopts['TARGET'] = self.target
            if 'DisablePayloadHandler' in runopts and runopts['DisablePayloadHandler']:
                pass
            elif payload is None:
                runopts['DisablePayloadHandler'] = True
            else:
                if isinstance(payload, PayloadModule):
                    if payload.modulename not in self.payloads:
                        raise ValueError(
                            'Invalid payload (%s) for given target (%d).' % (payload.modulename, self.target)
                        )
                    runopts['PAYLOAD'] = payload.modulename
                    for k, v in payload.runoptions.items():
                        if v is None or (isinstance(v, str) and not v):
                            continue
                        if k not in runopts or runopts[k] is None or \
                           (isinstance(runopts[k], str) and not runopts[k]):
                            runopts[k] = v
#                    runopts.update(payload.runoptions)
                elif isinstance(payload, str):
                    if payload not in self.payloads:
                        raise ValueError('Invalid payload (%s) for given target (%d).' % (payload, self.target))
                    runopts['PAYLOAD'] = payload
                else:
                    raise TypeError("Expected type str or PayloadModule not '%s'" % type(kwargs['payload']).__name__)
        runopts.update(kwargs.items())
        return self.rpc.call(MsfRpcMethod.ModuleExecute, self.moduletype, self.modulename, runopts)


class ExploitModule(MsfModule):

    def __init__(self, rpc, exploit):
        """
        Initializes the use of an exploit module.

        Mandatory Arguments:
        - rpc : the rpc client used to communicate with msfrpcd
        - exploit : the name of the exploit module.
        """
        super(ExploitModule, self).__init__(rpc, 'exploit', exploit)
        self._target = self._info.get('default_target', 0)

    @property
    def payloads(self):
        """
        A list of compatible payloads.
        """
#        return self.rpc.call(MsfRpcMethod.ModuleCompatiblePayloads, self.modulename)['payloads']
        return self.targetpayloads(self.target)

    @property
    def target(self):
        return self._target

    @target.setter
    def target(self, target):
        if target not in self.targets:
            raise ValueError('Target must be one of %s' % repr(list(self.targets.keys())))
        self._target = target

    def targetpayloads(self, t=0):
        """
        Returns a list of compatible payloads for a given target ID.

        Optional Keyword Arguments:
        - t : the target ID (default: 0, e.g. 'Automatic')
        """
        return self.rpc.call(MsfRpcMethod.ModuleTargetCompatiblePayloads, self.modulename, t)['payloads']


class PostModule(MsfModule):

    def __init__(self, rpc, post):
        """
        Initializes the use of a post exploitation module.

        Mandatory Arguments:
        - rpc : the rpc client used to communicate with msfrpcd
        - post : the name of the post exploitation module.
        """
        super(PostModule, self).__init__(rpc, 'post', post)

    @property
    def sessions(self):
        """
        A list of compatible shell/meterpreter sessions.
        """
        return self.rpc.compatiblesessions(self.modulename)


class EncoderModule(MsfModule):

    def __init__(self, rpc, encoder):
        """
        Initializes the use of an encoder module.

        Mandatory Arguments:
        - rpc : the rpc client used to communicate with msfrpcd
        - encoder : the name of the encoder module.
        """
        super(EncoderModule, self).__init__(rpc, 'encoder', encoder)


class AuxiliaryModule(MsfModule):

    def __init__(self, rpc, auxiliary):
        """
        Initializes the use of an auxiliary module.

        Mandatory Arguments:
        - rpc : the rpc client used to communicate with msfrpcd
        - auxiliary : the name of the auxiliary module.
        """
        super(AuxiliaryModule, self).__init__(rpc, 'auxiliary', auxiliary)


class PayloadModule(MsfModule):

    def __init__(self, rpc, payload):
        """
        Initializes the use of a payload module.

        Mandatory Arguments:
        - rpc : the rpc client used to communicate with msfrpcd
        - payload : the name of the payload module.
        """
        super(PayloadModule, self).__init__(rpc, 'payload', payload)


class NopModule(MsfModule):

    def __init__(self, rpc, nop):
        """
        Initializes the use of a nop module.

        Mandatory Arguments:
        - rpc : the rpc client used to communicate with msfrpcd
        - nop : the name of the nop module.
        """
        super(NopModule, self).__init__(rpc, 'nop', nop)


class ModuleManager(MsfManager):

    def execute(self, modtype, modname, **kwargs):
        """
        Execute the module.

        Mandatory Arguments:
        - modtype : the module type (e.g. 'exploit')
        - modname : the module name (e.g. 'exploits/windows/http/icecast_header')

        Optional Keyword Arguments:
        - **kwargs : the module's run options
        """
        return self.rpc.call(MsfRpcMethod.ModuleExecute, modtype, modname, kwargs)

    @property
    def exploits(self):
        """
        A list of exploit modules.
        """
        return self.rpc.call(MsfRpcMethod.ModuleExploits)['modules']

    @property
    def payloads(self):
        """
        A list of payload modules.
        """
        return self.rpc.call(MsfRpcMethod.ModulePayloads)['modules']

    @property
    def auxiliary(self):
        """
        A list of auxiliary modules.
        """
        return self.rpc.call(MsfRpcMethod.ModuleAuxiliary)['modules']

    @property
    def post(self):
        """
        A list of post modules.
        """
        return self.rpc.call(MsfRpcMethod.ModulePost)['modules']

    @property
    def encodeformats(self):
        """
        A list of encoding formats.
        """
        return self.rpc.call(MsfRpcMethod.ModuleEncodeFormats)

    @property
    def encoders(self):
        """
        A list of encoder modules.
        """
        return self.rpc.call(MsfRpcMethod.ModuleEncoders)['modules']

    @property
    def nops(self):
        """
        A list of nop modules.
        """
        return self.rpc.call(MsfRpcMethod.ModuleNops)['modules']

    def use(self, mtype, mname):
        """
        Returns a module object.

        Mandatory Arguments:
        - mname : the module name (e.g. 'exploits/windows/http/icecast_header')
        """
        if mtype == 'exploit':
            return ExploitModule(self.rpc, mname)
        elif mtype == 'post':
            return PostModule(self.rpc, mname)
        elif mtype == 'encoder':
            return EncoderModule(self.rpc, mname)
        elif mtype == 'auxiliary':
            return AuxiliaryModule(self.rpc, mname)
        elif mtype == 'nop':
            return NopModule(self.rpc, mname)
        elif mtype == 'payload':
            return PayloadModule(self.rpc, mname)
        raise MsfRpcError('Unknown module type %s not: exploit, post, encoder, auxiliary, nop, or payload' % mname)


class MsfSession(object):

    def __init__(self, id, rpc, sd):
        """
        Initialize a meterpreter or shell session.

        Mandatory Arguments:
        - id : the session identifier.
        - rpc : the msfrpc client object.
        - sd : the session description
        """
        self.id = id
        self.rpc = rpc
        self.__dict__.update(sd)

    def stop(self):
        """
        Stop a meterpreter or shell session.
        """
        return self.rpc.call(MsfRpcMethod.SessionStop, self.id)

    @property
    def modules(self):
        """
        A list of compatible session modules.
        """
        return self.rpc.call(MsfRpcMethod.SessionCompatibleModules, self.id)['modules']

    @property
    def ring(self):
        return SessionRing(self.rpc, self.id)


class SessionRing(object):

    def __init__(self, rpc, sessionid):
        self.rpc = rpc
        self.id = sessionid

    def read(self, seq=None):
        """
        Reads the session ring.

        Optional Keyword Arguments:
        - seq : the sequence ID of the ring (default: 0)
        """
        if seq is not None:
            return self.rpc.call(MsfRpcMethod.SessionRingRead, self.id, seq)
        return self.rpc.call(MsfRpcMethod.SessionRingRead, self.id)

    def put(self, line):
        """
        Add a command to the session history.

        Mandatory Arguments:
        - line : arbitrary data.
        """
        self.rpc.call(MsfRpcMethod.SessionRingPut, self.id, line)

    @property
    def last(self):
        """
        Returns the last sequence ID in the session ring.
        """
        return int(self.rpc.call(MsfRpcMethod.SessionRingLast, self.id)['seq'])

    def clear(self):
        """
        Clear the session ring.
        """
        return self.rpc.call(MsfRpcMethod.SessionRingClear, self.id)


class MeterpreterSession(MsfSession):

    def read(self):
        """
        Read data from the meterpreter session.
        """
        return self.rpc.call(MsfRpcMethod.SessionMeterpreterRead, self.id)['data']

    def write(self, data):
        """
        Write data to the meterpreter session.

        Mandatory Arguments:
        - data : arbitrary data or commands
        """
        self.rpc.call(MsfRpcMethod.SessionMeterpreterWrite, self.id, data)

    def runsingle(self, data):
        """
        Run a single meterpreter command

        Mandatory Arguments:
        - data : arbitrary data or command
        """
        self.rpc.call(MsfRpcMethod.SessionMeterpreterRunSingle, self.id, data)
        return self.read()

    def runscript(self, path):
        """
        Run a meterpreter script

        Mandatory Arguments:
        - path : path to a meterpreter script on the msfrpcd host.
        """
        self.rpc.call(MsfRpcMethod.SessionMeterpreterScript, self.id, path)
        return self.read()

    @property
    def sep(self):
        """
        The operating system path separator.
        """
        return self.rpc.call(MsfRpcMethod.SessionMeterpreterDirectorySeparator, self.id)['separator']

    def detach(self):
        """
        Detach the meterpreter session.
        """
        return self.rpc.call(MsfRpcMethod.SessionMeterpreterSessionDetach, self.id)

    def kill(self):
        """
        Kill the meterpreter session.
        """
        self.rpc.call(MsfRpcMethod.SessionMeterpreterSessionKill, self.id)

    def tabs(self, line):
        """
        Return a list of commands for a partial command line (tab completion).

        Mandatory Arguments:
        - line : a partial command line for completion.
        """
        return self.rpc.call(MsfRpcMethod.SessionMeterpreterTabs, self.id, line)['tabs']


class ShellSession(MsfSession):

    def read(self):
        """
        Read data from the shell session.
        """
        return self.rpc.call(MsfRpcMethod.SessionShellRead, self.id)['data']

    def write(self, data):
        """
        Write data to the shell session.

        Mandatory Arguments:
        - data : arbitrary data or commands
        """
        self.rpc.call(MsfRpcMethod.SessionShellWrite, self.id, data)

    def upgrade(self, lhost, lport):
        """
        Upgrade the current shell session.
        """
        self.rpc.call(MsfRpcMethod.SessionShellUpgrade, self.id, lhost, lport)
        return self.read()


class SessionManager(MsfManager):

    @property
    def list(self):
        """
        A list of active sessions.
        """
        return self.rpc.call(MsfRpcMethod.SessionList)

    def session(self, id):
        """
        Returns a session object for meterpreter or shell sessions.

        Mandatory Arguments:
        - id : the session identifier.
        """
        s = self.list
        if id not in s:
            for k in s:
                if s[k]['uuid'] == id:
                    if s[id]['type'] == 'meterpreter':
                        return MeterpreterSession(id, self.rpc, s)
                    elif s[id]['type']  == 'shell':
                        return ShellSession(id, self.rpc, s)
            raise KeyError('Session ID (%s) does not exist' % id)
        if s[id]['type'] == 'meterpreter':
            return MeterpreterSession(id, self.rpc, s)
        elif s[id]['type']  == 'shell':
            return ShellSession(id, self.rpc, s)
        raise NotImplementedError('Could not determine session type: %s' % s[id]['type'])


class MsfConsole(object):

    def __init__(self, rpc, cid=None):
        """
        Initializes an msf console.

        Mandatory Arguments:
        - rpc : the msfrpc client object.

        Optional Keyword Arguments:
        - cid : the console identifier if it exists already otherwise a new one will be created.
        """
        self.rpc = rpc
        if cid is None:
            r = self.rpc.call(MsfRpcMethod.ConsoleCreate)
            if 'id' in r:
                self.cid = r['id']
            else:
                raise MsfRpcError('Unable to create a new console.')
        else:
            self.cid = cid

    def read(self):
        """
        Read data from the console.
        """
        return self.rpc.call(MsfRpcMethod.ConsoleRead, self.cid)

    def write(self, command):
        """
        Write data to the console.
        """
        if not command.endswith('\n'):
            command += '\n'
        self.rpc.call(MsfRpcMethod.ConsoleWrite, self.cid, command)

    def sessionkill(self):
        """
        Kill all active meterpreter or shell sessions.
        """
        self.rpc.call(MsfRpcMethod.ConsoleSessionKill, self.cid)

    def sessiondetach(self):
        """
        Detach the current meterpreter or shell session.
        """
        self.rpc.call(MsfRpcMethod.ConsoleSessionDetach, self.cid)

    def tabs(self, line):
        """
        Tab completion for console commands.

        Mandatory Arguments:
        - line : a partial command to be completed.
        """
        return self.rpc.call(MsfRpcMethod.ConsoleTabs, self.cid, line)['tabs']

    def destroy(self):
        """
        Destroy the console.
        """
        self.rpc.call(MsfRpcMethod.ConsoleDestroy, self.cid)


class ConsoleManager(MsfManager):

    @property
    def list(self):
        """
        A list of active consoles.
        """
        return self.rpc.call(MsfRpcMethod.ConsoleList)

    def console(self, cid=None):
        """
        Connect to an active console otherwise create a new console.

        Optional Keyword Arguments:
        - cid : the console identifier.
        """
        s = self.list
        if cid is None:
            return MsfConsole(self.rpc)
        if cid not in s:
            raise KeyError('Console ID (%s) does not exist' % cid)
        else:
            return MsfConsole(self.rpc, cid=cid)

    def destroy(self, cid):
        """
        Destory an active console.

        Mandatory Arguments:
        - cid : the console identifier.
        """
        self.rpc.call(MsfRpcMethod.ConsoleDestroy, cid)

