
import os
from ConfigParser import ConfigParser

def getConnectionInfo():
    config_filename = os.path.join(os.path.dirname(__file__), os.path.pardir, 'connection.ini')
    cp = ConfigParser()
    cp.read(config_filename)

    info = {
        'server_name': cp.get('server', 'name'),
        'server_ip': cp.get('server', 'ip'),
        'server_port': cp.getint('server', 'port'),
        'client_name': cp.get('client', 'name'),
        'user': cp.get('user', 'name'),
        'password': cp.get('user', 'password'),
    }
    return info
