import json
import requests
import socks
import socket


socks.set_default_proxy(socks.SOCKS4, "localhost")
socket.socket = socks.socksocket

KEYSTONE_URL = 'http://172.16.0.2:5000/v3'
NEUTRON_URL = 'http://172.16.0.2:9696/v2.0'
NOVA_URL = ''
GLANCE_URL = ''
CINDER_URL = ''

ADMIN_USER = 'admin'
ADMIN_PASSWORD = 'admin'
ADMIN_TOKEN = 'VGMUUEkN'

EXTERNAL_NETWORK_ID = '282a5fd5-cbca-4f23-b287-40bb1d37192e'
IMAGE_ID = '8375a760-8724-4f7f-ba12-ed7d20691b8a'

HEADERS = {'Accept': 'application/json', 'Content-type': 'application/json'}


def auth_headers(token):
    headers = HEADERS
    headers['X-Auth-Token'] = token
    return headers


def get_domains():
    resp = requests.get('{}/domains'.format(KEYSTONE_URL), headers=auth_headers(ADMIN_TOKEN))
    return json.loads(resp.text)


def create_domain(name):
    body = \
        {
            'domain': {
                'name': name
            }
        }
    resp = requests.post('{}/domains'.format(KEYSTONE_URL), json.dumps(body), headers=auth_headers(ADMIN_TOKEN))
    return json.loads(resp.text)


def create_project(name, domain_id):
    body = \
        {
            'project': {
                'name': name,
                'domain_id': domain_id,
                'enabled': True
            }
        }
    resp = requests.post('{}/projects'.format(KEYSTONE_URL), json.dumps(body), headers=auth_headers(ADMIN_TOKEN))
    return json.loads(resp.text)


def get_projects():
    resp = requests.get('{}/projects'.format(KEYSTONE_URL), headers=auth_headers(ADMIN_TOKEN))
    return json.loads(resp.text)


def create_user(username, password, domain_id, project):
    body = \
        {
            'user': {
                'name': username,
                'password': password,
                'domain_id': domain_id,
                'default_project': project
            }
        }

    resp = requests.post('{}/users'.format(KEYSTONE_URL), json.dumps(body), headers=auth_headers(ADMIN_TOKEN))
    return json.loads(resp.text)


def delete_user(id):
    resp = requests.delete('{}/users/{}'.format(KEYSTONE_URL, id), headers=auth_headers(ADMIN_TOKEN))
    return json.loads(resp.text)


def get_users():
    resp = requests.get('{}/users'.format(KEYSTONE_URL), headers=auth_headers(ADMIN_TOKEN))
    return resp.text


def get_user_roles(id):
    resp = requests.get('{}/users/{}/roles'.format(KEYSTONE_URL, id), headers=auth_headers(ADMIN_TOKEN))
    return json.loads(resp.text)


def get_user_roles_in_project(project, user):
    resp = requests.get('{}/projects/{}/users/{}/roles'.format(KEYSTONE_URL, project, user), headers=auth_headers(ADMIN_TOKEN))
    return json.loads(resp.text)


def grant_user_role_in_project(project, user, role):
    resp = requests.put('{}/projects/{}/users/{}/roles/{}'.format(KEYSTONE_URL, project, user, role), headers=auth_headers(ADMIN_TOKEN))
    return resp.text


def get_roles():
    resp = requests.get('{}/roles'.format(KEYSTONE_URL), headers=auth_headers(ADMIN_TOKEN))
    return json.loads(resp.text)


def get_token(username, password, domain, project):
    body = \
        {
            'auth': {
                'identity': {
                    'methods': [
                        'password'
                    ],
                    'password': {
                        'user': {
                            'domain': {
                                'name': domain
                            },
                            'name': username,
                            'password': password
                        }
                    }
                },
                'scope': {
                    'project': {
                        'domain': {
                            'name': domain
                        },
                        'name': project
                    }
                }
            }
        }

    resp = requests.post('{}/auth/tokens'.format(KEYSTONE_URL), json.dumps(body), headers=HEADERS)
    return resp.headers


def create_network(token, name):
    body = \
        {
            'network': {
                'name': name
            }
        }

    resp = requests.post('{}/networks'.format(NEUTRON_URL), json.dumps(body), headers=auth_headers(token))
    return json.loads(resp.text)


def create_subnet(token, network_id):
    body = \
        {
            'subnet': {
                'ip_version': 4,
                'cidr': '90.91.92.0/24',
                'network_id': network_id
            }
        }

    resp = requests.post('{}/subnets'.format(NEUTRON_URL), json.dumps(body), headers=auth_headers(token))
    return json.loads(resp.text)


def create_router(token, name, gw_network_id):
    body = \
        {
            'router': {
                'name': name,
                'external_gateway_info': {
                    'network_id': gw_network_id
                }
            }
        }

    resp = requests.post('{}/routers'.format(NEUTRON_URL), json.dumps(body), headers=auth_headers(token))
    return json.loads(resp.text)


def add_router_interface(token, router_id, subnet_id):
    body = \
        {
            'subnet_id': subnet_id
        }

    resp = requests.put('{}/routers/{}/add_router_interface'.format(NEUTRON_URL, router_id), json.dumps(body), headers=auth_headers(token))
    return json.loads(resp.text)



DOMAIN = 'my_dom_98'
PROJECT = 'my_proj_98'
USER = 'my_usr_98'
NETWORK = 'my_net_98'
ROUTER = 'my_router_98'
SSH_KEY = 'my_key_98'
INSTANCE = 'my_instance_98'
VOLUME = 'my_volume_98'

domain_id = create_domain(DOMAIN)['domain']['id']
print 'DOMAIN ID: {}'.format(domain_id)

project_id = create_project(PROJECT, domain_id)['project']['id']
print 'PROJECT ID: {}'.format(project_id)

user_id = create_user(USER, '123qwe', domain_id, PROJECT)['user']['id']
print 'USER ID: {}'.format(user_id)

roles = get_roles()['roles']
for role in roles:
    if role['name'] == '_member_':
        member_role_id = role['id']
print 'MEMBER ROLE ID: {}'.format(member_role_id)

grant_user_role_in_project(project_id, user_id, member_role_id)

token = get_token(USER, '123qwe', DOMAIN, PROJECT)['x-subject-token']
print 'TOKEN: {}'.format(token)

network_id = create_network(token, NETWORK)['network']['id']
print 'NETWORK ID: {}'.format(network_id)

subnet_id = create_subnet('fbd38d1ee7f4497db6012cd7908d10c3', 'd47a3be5-3b43-4f5f-86ff-e97ecc8375d6')['subnet']['id']
print 'SUBNET_ID: {}'.format(subnet_id)

router_id = create_router('fbd38d1ee7f4497db6012cd7908d10c3', ROUTER, EXTERNAL_NETWORK_ID)['router']['id']
print 'ROUTER_ID: {}'.format(router_id)

interface_id = add_router_interface('fbd38d1ee7f4497db6012cd7908d10c3', '73d81578-0c59-4ae2-8bbd-93935f9dac20', '25959a9b-03e5-4e25-b4ba-63dec9a9e7f9')
print 'INTERFACE_ID: {}'.format(interface_id)



