import json
import requests
import random
import time

from colorama import Fore


# Uncomment to connect through a SOCKS4 proxy
import socks
import socket
socks.set_default_proxy(socks.SOCKS4, "localhost")
socket.socket = socks.socksocket


KEYSTONE_URL = 'http://172.16.0.2:5000/v3'
NEUTRON_URL = 'http://172.16.0.2:9696/v2.0'
NOVA_URL = 'http://172.16.0.2:8774/v2'
CINDER_URL = 'http://172.16.0.2:8776/v1'

ADMIN_USER = 'admin'
ADMIN_PASSWORD = 'admin'
ADMIN_TOKEN = 'VGMUUEkN'

EXTERNAL_NETWORK_ID = '51942ec0-6dd2-4844-bd24-7a2dd3ed4f04'
IMAGE_ID = 'c3d7a902-1d2e-4500-bd28-bfebdd3e5208'
FLAVOR_ID = 'fb768565-5062-4fa7-8142-d103844f260d'

HEADERS = {'Accept': 'application/json', 'Content-type': 'application/json'}


def service_request(service_endpoint, method, path, headers, body=None):
    print '=== R E Q U E S T ===\n' \
          'METHOD:  {}\n' \
          'URL:     {}\n' \
          'HEADERS: {}'.format(method.upper(), service_endpoint + path, headers)
    if body:
        print 'BODY:    {}'.format(body) if body else None

    if body:
        resp = getattr(requests, method)('{}/{}'.format(service_endpoint, path), json.dumps(body), headers=headers)
    else:
        resp = getattr(requests, method)('{}/{}'.format(service_endpoint, path), headers=headers)

    response_log = '=== R E S P O N S E ===\n' \
                   'CODE:    {}\n' \
                   'HEADERS: {}\n' \
                   'BODY:    {}\n'.format(resp.status_code, dict(resp.headers), resp.text)
    if resp.status_code > 300:
        print(Fore.RED + response_log + Fore.RESET)
    else:
        print(Fore.GREEN + response_log + Fore.RESET)

    try:
        resp_body = resp.json()
    except ValueError:
        resp_body = resp.text

    return {'headers': resp.headers, 'body': resp_body}


def auth_headers(token):
    headers = HEADERS
    headers['X-Auth-Token'] = token
    return headers


def get_domains():
    return service_request(KEYSTONE_URL, 'get', '/domains', auth_headers(ADMIN_TOKEN))


def create_domain(name):
    body = \
        {
            'domain': {
                'name': name
            }
        }
    return service_request(KEYSTONE_URL, 'post', '/domains', auth_headers(ADMIN_TOKEN), body)


def create_project(name, domain_id):
    body = \
        {
            'project': {
                'name': name,
                'domain_id': domain_id,
                'enabled': True
            }
        }
    return service_request(KEYSTONE_URL, 'post', '/projects', auth_headers(ADMIN_TOKEN), body)


def get_projects():
    return service_request(KEYSTONE_URL, 'get', '/projects', auth_headers(ADMIN_TOKEN))


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
    return service_request(KEYSTONE_URL, 'post', '/users', auth_headers(ADMIN_TOKEN), body)


def delete_user(user_id):
    return service_request(KEYSTONE_URL, 'delete', '/users/{}'.format(user_id), auth_headers(ADMIN_TOKEN))


def get_users():
    return service_request(KEYSTONE_URL, 'get', '/users', auth_headers(ADMIN_TOKEN))


def get_user_roles(user_id):
    return service_request(KEYSTONE_URL, 'get', '/users/{}/roles'.format(user_id), auth_headers(ADMIN_TOKEN))


def get_user_roles_in_project(tenant_id, user_id):
    return service_request(KEYSTONE_URL, 'get', '/projects/{}/users/{}/roles'.format(tenant_id, user_id), auth_headers(ADMIN_TOKEN))


def grant_user_role_in_project(tenant_id, user_id, role_id):
    return service_request(KEYSTONE_URL, 'put', '/projects/{}/users/{}/roles/{}'.format(tenant_id, user_id, role_id), auth_headers(ADMIN_TOKEN))


def get_roles():
    return service_request(KEYSTONE_URL, 'get', '/roles', auth_headers(ADMIN_TOKEN))


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
    return service_request(KEYSTONE_URL, 'post', '/auth/tokens', HEADERS, body)


def create_network(token, name):
    body = \
        {
            'network': {
                'name': name
            }
        }
    return service_request(NEUTRON_URL, 'post', '/networks', auth_headers(token), body)


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
    return service_request(NEUTRON_URL, 'post', '/subnets', auth_headers(token), body)


def create_router(token, name, network_id):
    body = \
        {
            'router': {
                'name': name,
                'external_gateway_info': {
                    'network_id': network_id
                }
            }
        }
    return service_request(NEUTRON_URL, 'post', '/routers', auth_headers(token), body)


def add_router_interface(token, router_id, subnet_id):
    body = \
        {
            'subnet_id': subnet_id
        }
    return service_request(NEUTRON_URL, 'put', '/routers/{}/add_router_interface'.format(router_id), auth_headers(token), body)


def create_keypair(token, tenant_id, name):
    body = \
        {
            'keypair': {
                'name': name
            }
        }
    return service_request(NOVA_URL, 'post', '/{}/os-keypairs'.format(tenant_id), auth_headers(token), body)


def create_instance(token, name, tenant_id, flavor_id, image_id, network_id):
    body = \
        {
            'server': {
                'flavorRef': flavor_id,
                'imageRef': image_id,
                'name': name,
                'networks': [
                    {
                        'uuid': network_id
                    }
                ]
            }
        }
    return service_request(NOVA_URL, 'post', '/{}/servers'.format(tenant_id), auth_headers(token), body)


def get_instance(token, tenant_id, instance_id):
    return service_request(NOVA_URL, 'get', '/{}/servers/{}'.format(tenant_id, instance_id), auth_headers(token))


def create_volume(token, tenant_id, name, size):
    body = \
        {
            'volume': {
                'display_name': name,
                'size': size
            }
        }
    return service_request(CINDER_URL, 'post', '/{}/volumes'.format(tenant_id), auth_headers(token), body)


def attach_volume(token, tenant_id, instance_id, volume_id):
    body = \
        {
            'volumeAttachment': {
                'volumeId': volume_id,
                'device': '/dev/vdd'
                          ''
            }
        }
    return service_request(NOVA_URL, 'post', '/{}/servers/{}/os-volume_attachments'.format(tenant_id, instance_id), auth_headers(token), body)


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
    'DOMAIN:   {}\n' \
    'PROJECT:  {}\n' \
    'USER:     {}\n' \
    'PASSWORD: 123qwe\n' \
    'NETWORK:  {}\n' \
    'ROUTER:   {}\n' \
    'KEYPAIR:  {}\n' \
    'INSTANCE: {}\n' \
    'VOLUME:   {}\n'.format(DOMAIN, PROJECT, USER, NETWORK, ROUTER, KEYPAIR, INSTANCE, VOLUME)

# Create domain
domain_id = create_domain(DOMAIN)['body']['domain']['id']

# Create project
tenant_id = create_project(PROJECT, domain_id)['body']['project']['id']

# Create user
user_id = create_user(USER, '123qwe', domain_id, PROJECT)['body']['user']['id']

# Assign role to user
roles = get_roles()['body']['roles']
for role in roles:
    if role['name'] == '_member_':
        member_role_id = role['id']
grant_user_role_in_project(tenant_id, user_id, member_role_id)

# Get token
token = get_token(USER, '123qwe', DOMAIN, PROJECT)['headers']['x-subject-token']

# Create network
network_id = create_network(token, NETWORK)['body']['network']['id']

# Create subnet
subnet_id = create_subnet(token, network_id)['body']['subnet']['id']

# Create router
router_id = create_router(token, ROUTER, EXTERNAL_NETWORK_ID)['body']['router']['id']

# Add router interface for internal network
interface_id = add_router_interface(token, router_id, subnet_id)['body']['id']

# Create keypair
keypair_name = create_keypair(token, tenant_id, KEYPAIR)['body']['keypair']['name']

# Create instance
instance_id = create_instance(token, INSTANCE, tenant_id, FLAVOR_ID, IMAGE_ID, network_id)['body']['server']['id']

# Wait for the instance to build
print 'Waiting 10 seconds for the instance to finish building'
time.sleep(10)

# Show instance details
get_instance(token, tenant_id, instance_id)

# Create volume
volume_id = create_volume(token, tenant_id, VOLUME, 2)['body']['volume']['id']

# Attach volume to instance
attach_volume(token, tenant_id, instance_id, volume_id)
