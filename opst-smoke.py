import json
import requests
import socks
import socket
import random
import time


# Uncomment to connect through a SOCKS4 proxy
socks.set_default_proxy(socks.SOCKS4, "localhost")
socket.socket = socks.socksocket


KEYSTONE_URL = 'http://172.16.0.2:5000/v3'
NEUTRON_URL = 'http://172.16.0.2:9696/v2.0'
NOVA_URL = 'http://172.16.0.2:8774/v2'
GLANCE_URL = ''
CINDER_URL = 'http://172.16.0.2:8776/v1'

ADMIN_USER = 'admin'
ADMIN_PASSWORD = 'admin'
ADMIN_TOKEN = 'VGMUUEkN'

EXTERNAL_NETWORK_ID = '542787ef-186a-4d37-9b3d-68b8f23cbfec'
IMAGE_ID = '10758a3d-e0a0-43eb-b93d-fbc054686e98'
FLAVOR_ID = '1'

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
    ip = ".".join(map(str, (random.randint(0, 255) for _ in range(3))))
    cidr = '{}.0/24'.format(ip)
    body = \
        {
            'subnet': {
                'ip_version': 4,
                'cidr': cidr,
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


def create_keypair(token, tenant_id, name):
    body = \
        {
            'keypair': {
                'name': name
            }
        }

    resp = requests.post('{}/{}/os-keypairs'.format(NOVA_URL, tenant_id), json.dumps(body), headers=auth_headers(token))
    return json.loads(resp.text)


def create_instance(token, tenant_id, flavor, image, name, network_id):
    body = \
        {
            'server': {
                'flavorRef': flavor,
                'imageRef': image,
                'name': name,
                'networks': [
                    {
                        'uuid': network_id
                    }
                ]
            }
        }

    resp = requests.post('{}/{}/servers'.format(NOVA_URL, tenant_id), json.dumps(body), headers=auth_headers(token))
    return json.loads(resp.text)


def get_instance(token, tenant_id, instance_id):
    resp = requests.get('{}/{}/servers/{}'.format(NOVA_URL, tenant_id, instance_id), headers=auth_headers(token))
    return json.loads(resp.text)


def create_volume(token, tenant_id, name, size):
    body = \
        {
            'volume': {
                'display_name': name,
                'size': size
            }
        }

    resp = requests.post('{}/{}/volumes'.format(CINDER_URL, tenant_id), json.dumps(body), headers=auth_headers(token))
    return json.loads(resp.text)


def attach_volume(token, tenant_id, instance_id, volume_id):
    body = \
        {
            'volumeAttachment': {
                'volumeId': volume_id
            }
        }

    resp = requests.post('{}/{}/servers/{}/os-volume_attachments'.format(NOVA_URL, tenant_id, instance_id), json.dumps(body), headers=auth_headers(token))
    return json.loads(resp.text)



suffix = repr(random.random())[2:]

DOMAIN   = 'my_doma_{}'.format(suffix)
PROJECT  = 'my_proj_{}'.format(suffix)
USER     = 'my_user_{}'.format(suffix)
NETWORK  = 'my_netw_{}'.format(suffix)
ROUTER   = 'my_rout_{}'.format(suffix)
KEYPAIR  = 'my_keyp_{}'.format(suffix)
INSTANCE = 'my_inst_{}'.format(suffix)
VOLUME   = 'my_volu_{}'.format(suffix)

print \
    'DOMAIN: {}\n' \
    'PROJECT: {}\n' \
    'USER: {}\n' \
    'PASSWORD: 123qwe\n' \
    'NETWORK: {}\n' \
    'ROUTER: {}\n' \
    'KEYPAIR: {}\n' \
    'INSTANCE: {}\n' \
    'VOLUME: {}\n'.format(DOMAIN, PROJECT, USER, NETWORK, ROUTER, KEYPAIR, INSTANCE, VOLUME)

# Create domain
domain_id = create_domain(DOMAIN)['domain']['id']
print 'DOMAIN ID: {}'.format(domain_id)

# Create project
project_id = create_project(PROJECT, domain_id)['project']['id']
print 'PROJECT ID: {}'.format(project_id)

# Create user
user_id = create_user(USER, '123qwe', domain_id, PROJECT)['user']['id']
print 'USER ID: {}'.format(user_id)

# Assign role to user
roles = get_roles()['roles']
for role in roles:
    if role['name'] == '_member_':
        member_role_id = role['id']
print 'MEMBER ROLE ID: {}'.format(member_role_id)
grant_user_role_in_project(project_id, user_id, member_role_id)

# Get token
token = get_token(USER, '123qwe', DOMAIN, PROJECT)['x-subject-token']
print 'TOKEN: {}'.format(token)

# Create network
network_id = create_network(token, NETWORK)['network']['id']
print 'NETWORK ID: {}'.format(network_id)

# Create subnet
subnet_id = create_subnet(token, network_id)['subnet']['id']
print 'SUBNET_ID: {}'.format(subnet_id)

# Create router
router_id = create_router(token, ROUTER, EXTERNAL_NETWORK_ID)['router']['id']
print 'ROUTER_ID: {}'.format(router_id)

# Add router interface for internal network
interface_id = add_router_interface(token, router_id, subnet_id)['id']
print 'INTERFACE_ID: {}'.format(interface_id)

# Create keypair
keypair_name = create_keypair(token, project_id, KEYPAIR)['keypair']['name']
print 'KEYPAIR NAME: {}'.format(keypair_name)

# Create instance
instance_id = create_instance(token, project_id, FLAVOR_ID, IMAGE_ID, INSTANCE, network_id)['server']['id']
print 'INSTANCE ID: {}'.format(instance_id)

# Show instance details
print get_instance(token, project_id, instance_id)

# Create volume
volume_id = create_volume(token, project_id, VOLUME, 2)['volume']['id']
print 'VOLUME ID: {}'.format(volume_id)

# Wait for the instance to finish building
time.sleep(10)

# Attach volume to instance
volume_attach_response = attach_volume(token, project_id, instance_id, volume_id)
print volume_attach_response
