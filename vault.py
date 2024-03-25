# References:
# https://developer.hashicorp.com/hcp/api-docs/vault-secrets#overview
# https://developer.hashicorp.com/vault/tutorials/secrets-management/static-secrets
# https://developer.hashicorp.com/vault/tutorials/auth-methods/approle
# https://developer.hashicorp.com/vault/api-docs/auth/approle
# https://developer.hashicorp.com/vault/docs/concepts/tokens#root-tokens
# https://developer.hashicorp.com/vault/api-docs/secret/databases

import requests
import ssl

# https://stackoverflow.com/questions/61631955/python-requests-ssl-error-during-requests
class TLSAdapter(requests.adapters.HTTPAdapter):
    def init_poolmanager(self, *args, **kwargs):
        ctx = ssl.create_default_context()
        ctx.set_ciphers('DEFAULT@SECLEVEL=1')
        kwargs['ssl_context'] = ctx
        return super(TLSAdapter, self).init_poolmanager(*args, **kwargs)

class Vault_Cloud:

    def __init__(self, app_client, app_secret, org_id, project_id, app_name):        
        self.app_client = app_client
        self.app_secret = app_secret
        self.org_id = org_id
        self.project_id = project_id
        self.app_name = app_name

        self.token_url = 'https://auth.idp.hashicorp.com/oauth2'
        self.secret_url = f'https://api.cloud.hashicorp.com/secrets/2023-06-13/organizations/{self.org_id}/projects/{self.project_id}/apps/{self.app_name}'
        return
    
    
    def get_token(self):
        r = requests.post(
            url = f'{self.token_url}/token', 
            headers = {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            data = {
                'client_id': self.app_client,
                'client_secret': self.app_secret,
                'grant_type': 'client_credentials',
                'audience': 'https://api.hashicorp.cloud'
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to get token ! {r.json()}')
 
        token = r.json()['access_token']
        return token
    
    
    def list_secrets(self, token):
        # Require viewer role
        secrets = {}
        r = requests.get(
            url = f'{self.secret_url}/open',
            headers = {
                'Authorization': f'Bearer {token}'
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to list secrets ! {r.json()}')
        
        for secret in r.json()['secrets']:
            secret_name = secret['name']
            secret_value = secret['version']['value']
            secrets[secret_name] = secret_value
        return secrets


    def get_secret(self, token, secret_name):
        # Require viewer role
        secret = {}
        r = requests.get(
            url = f'{self.secret_url}/open/{secret_name}',
            headers = {
                'Authorization': f'Bearer {token}'
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to get secret ! {r.json()}')
        
        secret_value = r.json()['secret']['version']['value']
        secret[secret_name] = secret_value
        return secret


    def create_secret(self, token, secret_name, secret_value):
        # Require contributor role
        r = requests.post(
            url = f'{self.secret_url}/kv',
            headers = {
                'Authorization': f'Bearer {token}'
            },
            json = {
                # 'location': {
                #     'region': {
                #         'provider': 'aws',
                #         'region': 'us-west1'
                #     }
                # },
                'name': secret_name,
                'value': secret_value
            },
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to create secret ! {r.json()}')
        
        return r.json()
    

    def delete_secret(self, token, secret_name):
        # Require contributor role
        r = requests.delete(
            url = f'{self.secret_url}/secrets/{secret_name}',
            headers = {
                'Authorization': f'Bearer {token}'
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to delete secret ! {r.json()}')
        
        return f'Successfully deleted {secret_name}'
    

class Vault_Cluster:

    def __init__(self, vault_url, namespace):        
        self.vault_url = vault_url
        self.namespace = namespace

        self.session = requests.session()
        self.session.mount('https://', TLSAdapter())
        return

        
    def get_ldap_token(self, ldap_user, ldap_password):
        r = self.session.post(
            url = f'{self.vault_url}/v1/auth/ldap/login/{ldap_user}',
            json = {
                'password': ldap_password
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to get ldap_token ! {r.json()}')
        ldap_token = r.json()['auth']['client_token']
        return ldap_token
    

    def list_auths(self, token):
        r = self.session.get(
            url = f'{self.vault_url}/v1/sys/auth',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to list auths ! {r.json()}')
        return r.json() 
    

    def get_auth(self, token, auth_type):
        r = self.session.get(
            url = f'{self.vault_url}/v1/sys/auth/{auth_type}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to get auth ! {r.json()}')
        return r.json()
    

    def enable_auth(self, token, auth_type):
        r = self.session.post(
            url = f'{self.vault_url}/v1/sys/auth/{auth_type}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            },
            json = {
                'type': {auth_type}
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to enable auth ! {r.json()}')
        return r.json()
    

    def disable_auth(self, token, auth_type):
        r = self.session.delete(
            url = f'{self.vault_url}/v1/sys/auth/{auth_type}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to disable auth !')
        return 'Successfully disable auth !'


    def list_policies(self, token):
        r = self.session.request(
            method = 'LIST',
            url = f'{self.vault_url}/v1/sys/policies/acl',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to list policies ! {r.json()}')
        return r.json()
    

    def get_policy(self, token, policy_name):
        r = self.session.get(
            url = f'{self.vault_url}/v1/sys/policies/acl/{policy_name}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to get policy ! {r.json()}')
        return r.json()


    def create_policy(self, token, policy_name, secret_path, capabilities=["read"]):
        # capabilities = ["create", "read", "update", "patch", "delete", "list"]
        cp = str(capabilities).replace('\'', '\"')
        r = self.session.post(
            url = f'{self.vault_url}/v1/sys/policies/acl/{policy_name}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            },
            json = {
                "policy": f"path \"{secret_path}\" {{ capabilities = [{cp}] }}"
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to create policy !')
        return 'Successfully created or updated policy !'


    def delete_policy(self, token, policy_name):
        r = self.session.delete(
            url = f'{self.vault_url}/v1/sys/policies/acl/{policy_name}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to delete policy !')
        return 'Successfully deleted policy !'

    
    def list_roles(self, token):
        r = self.session.request(
            method = 'LIST',
            url = f'{self.vault_url}/v1/auth/approle/role',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to list roles ! {r.json()}')
        return r.json()


    def get_role(self, token, role_name):
        r = self.session.get(
            url = f'{self.vault_url}/v1/auth/approle/role/{role_name}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to get role ! {r.json()}')
        return r.json()  


    def create_role(self, token, role_name, token_policies=['default']):
        r = self.session.post(
            url = f'{self.vault_url}/v1/auth/approle/role/{role_name}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            },
            json = {
                'bind_secret_id': True,
                'secret_id_num_uses': 0,
                'secret_id_ttl': 0,
                'local_secret_ids': False,
                'token_ttl': '10m',
                'token_max_ttl': '30m',
                'token_policies': token_policies,
                'token_no_default_policiy': False,
                'token_num_uses': 0,
                'token_period': 0,
                'token_type': 'service'
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to create role ! {r.json()}')
        return r.json()    


    def delete_role(self, token, role_name):
        r = self.session.delete(
            url = f'{self.vault_url}/v1/auth/approle/role/{role_name}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to delete role !')
        return 'Successfully delete role !'   


    def get_role_id(self, token, role_name):
        r = self.session.get(
            url = f'{self.vault_url}/v1/auth/approle/role/{role_name}/role-id',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to get role_id ! {r.json()}')
        role_id = r.json()['data']['role_id']
        return role_id   


    def create_secret_id(self, token, role_name):
        r = self.session.post(
            url = f'{self.vault_url}/v1/auth/approle/role/{role_name}/secret-id',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            },
            json = {
                'ttl': 600,
                'num_uses': 0
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to create secret_id ! {r.json()}')
        secret_id = r.json()['data']['secret_id']
        return secret_id
    

    def destroy_secret_id(self, token, role_name, secret_id):
        r = self.session.post(
            url = f'{self.vault_url}/v1/auth/approle/role/{role_name}/secret-id/destroy',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            },
            json = {
                'secret_id': secret_id
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to destroy secret_id ! {r.json()}')
        return r.json()  


    def get_app_token(self, token, role_id, secrect_id):
        r = self.session.post(
            url = f'{self.vault_url}/v1/auth/approle/login',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            },
            json = {
                'role_id': role_id,
                'secret_id': secrect_id
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to get app token ! {r.json()}')
        app_token = r.json()['auth']['client_token']
        return app_token


    def list_engines(self, token):
        r = self.session.get(
            url = f'{self.vault_url}/v1/sys/mounts',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to list engines ! {r.json()}')
        return r.json()


    def get_engine(self, token, engine_name):
        r = self.session.get(
            url = f'{self.vault_url}/v1/sys/mounts/{engine_name}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to get engine ! {r.json()}')
        return r.json()
    

    def create_engine(self, token, engine_name, engine_type):
        r = self.session.post(
            url = f'{self.vault_url}/v1/sys/mounts/{engine_name}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            },
            data = {
                'type': engine_type
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to create engine !')
        return 'Successfully createed engine !'
    

    def delete_engine(self, token, engine_name):
        r = self.session.delete(
            url = f'{self.vault_url}/v1/sys/mounts/{engine_name}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to delete engine !')
        return 'Successfully deleted engine !'
    
    
    def list_secrets(self, token, engine_name, secret_path):
        r = self.session.request(
            method = 'LIST',
            url = f'{self.vault_url}/v1/{engine_name}/metadata/{secret_path}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to list secrets ! {r.json()}')
        return r.json()
    
    
    def get_secret(self, token, engine_name, secret_path, version=0):
        headers = {
            'X-Vault-Token': token,
            'X-Vault-Namespace': self.namespace,
        }
        # if wrap:
        #     headers['X-Vault-Wrap-TTL'] = 120
        r = self.session.get(
            url = f'{self.vault_url}/v1/{engine_name}/data/{secret_path}',
            headers = headers,
            params = {
                'version': version
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to get secret ! {r.json()}')
        secret = r.json()['data']['data']
        version = r.json()['data']['metadata']['version']
        return secret, version
    

    def unwrap_secret(self, wrapping_token):
        r = self.session.post(
            url = f'{self.vault_url}/v1/sys/wrapping/unwrap',
            headers = {
                'X-Vault-Token': wrapping_token,
                'X-Vault-Namespace': self.namespace,
            },
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to unwrap secret ! {r.json()}')
        secret = r.json()['data']
        return secret
    
    
    def create_secret(self, token, engine_name, secret_path, secret_data):
        r = self.session.post(
            url = f'{self.vault_url}/v1/{engine_name}/data/{secret_path}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            },
            json = {
                'data': secret_data,
                # 'custom_metadata': {

                # }
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to create secret ! {r.json()}')
        return r.json()
    

    def update_secret(self, token, engine_name, secret_path, secret_data):
        r = self.session.patch(
            url = f'{self.vault_url}/v1/{engine_name}/data/{secret_path}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace,
                'Content-Type': 'application/merge-patch+json'
            },
            json = {
                'data': secret_data
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to update secret ! {r.json()}')
        return r.json()
    
    
    def delete_secret(self, token, engine_name, secret_path, versions=[]):
        if len(versions) < 1:
            r = self.session.post(
                url = f'{self.vault_url}/v1/{engine_name}/delete/{secret_path}',
                headers = {
                    'X-Vault-Token': token,
                    'X-Vault-Namespace': self.namespace
                }
            )
        else:
            r = self.session.post(
                url = f'{self.vault_url}/v1/{engine_name}/delete/{secret_path}',
                headers = {
                    'X-Vault-Token': token,
                    'X-Vault-Namespace': self.namespace
                },
                json = {
                    'versions': versions
                }
            )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to delete secret !')
        return 'Successfully deleted secret !'
    
    
    def undelete_secret(self, token, engine_name, secret_path, versions):
        r = self.session.post(
            url = f'{self.vault_url}/v1/{engine_name}/undelete/{secret_path}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            },
            json = {
                'versions': versions
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to undelete secret !')
        return 'Successfully undelete secret !'
    

    def destroy_secret(self, token, engine_name, secret_path, versions):
        r = self.session.post(
            url = f'{self.vault_url}/v1/{engine_name}/destroy/{secret_path}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            },
            json = {
                'versions': versions
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to destroy secret !')
        return 'Successfully destroyed secret !'
    

    def destroy_secrets(self, token, engine_name, secret_path):
        r = self.session.delete(
            url = f'{self.vault_url}/v1/{engine_name}/metadata/{secret_path}',
            headers = {
                'X-Vault-Token': token,
                'X-Vault-Namespace': self.namespace
            }
        )
        if r.status_code != 200 and r.status_code != 204:
            raise AssertionError(f'[{r.status_code}] Failed to destroy secrets !')
        return 'Successfully destroyed secrets !'
    

if __name__ == '__main__':

    # vault_type = 'cloud'
    vault_type = 'cluster'

    if vault_type == 'cloud':

        # Init vault_cloud
        vault_cloud = Vault_Cloud(
            app_client='XXXXXXXXXXXXXXXXXXXX', 
            app_secret='XXXXXXXXXXXXXXXXXXX',
            org_id = '1776a674-5d79-43af-8511-6942ccf9d701',
            project_id = 'f3ea2563-6385-467a-b5ee-76d6149b1c63',
            app_name = 'sample-app',
        )

        token = vault_cloud.get_token()

        # print(vault_cloud.list_secrets(token=token))

        print(vault_cloud.get_secret(token=token, secret_name='key1'))

        # print(vault_cloud.create_secret(token=token, secret_name='key2', secret_value='v2'))

        # print(vault_cloud.delete_secret(token=token, secret_name='key2'))

    elif vault_type == 'cluster':

        # Init vault_cluster
        vault_cluster = Vault_Cluster(
            vault_url = 'https://vault.micron.com',
            namespace = 'mmpnpi'
        )

        # ldap_token = vault_cluster.get_ldap_token(ldap_user='user', ldap_password='pwd')
        # print(ldap_token)

        # auths = vault_cluster.list_auths(token=ldap_token)
        # print(auths)

        # auth = vault_cluster.get_auth(token=ldap_token, auth_type='approle')
        # print(auth)

        # approle_enable = vault_cluster.enable_auth(token=ldap_token, auth_type='approle')
        # print(approle_enable)

        # approle_disable = vault_cluster.disable_auth(token=ldap_token, auth_type='approle')
        # print(approle_disable)

        # policies = vault_cluster.list_policies(token=ldap_token)
        # print(policies)

        # policy = vault_cluster.get_policy(token=ldap_token, policy_name='admin-temp')
        # print(policy)

        # policy_create = vault_cluster.create_policy(token=ldap_token, policy_name='admin-temp', secret_path='path1*', capabilities=["create", "read", "update", "patch", "delete", "list"])
        # print(policy_create)

        # policy_delete = vault_cluster.delete_policy(token=ldap_token, policy_name='admin-temp')
        # print(policy_delete)

        # roles = vault_cluster.list_roles(token=ldap_token)
        # print(roles)

        # role = vault_cluster.get_role(token=ldap_token, role_name='sample-role')
        # print(role)

        # role_create = vault_cluster.create_role(token=ldap_token, role_name='sample-role', token_policies=['admin-temp'])
        # print(role_create)

        # role_delete = vault_cluster.delete_role(token=ldap_token, role_name='sample-role')
        # print(role_delete)

        # role_id = vault_cluster.get_role_id(token=ldap_token, role_name='sample-role')
        # print(role_id)

        # secret_id = vault_cluster.create_secret_id(token=ldap_token, role_name='sample-role')
        # print(secret_id)

        # secret_id_destroy = vault_cluster.destroy_secret_id(token=ldap_token, secret_id=secret_id)
        # print(secret_id_destroy)

        # app_token = vault_cluster.get_app_token(token=ldap_token, role_id=role_id, secrect_id=secret_id)
        # print(app_token)

        # engines = vault_cluster.list_engines(token=app_token)
        # print(engines)

        # engine_create = vault_cluster.create_engine(token=app_token, engine_name='kv', engine_type='kv-v2')
        # print(engine_create)

        # engine_delete = vault_cluster.delete_engine(token=app_token, engine_name='kv')
        # print(engine_delete)

        # secrets = vault_cluster.list_secrets(token=app_token, engine_name='kv', secret_path='path1')
        # print(secrets)

        # secret, version = vault_cluster.get_secret(token=app_token, engine_name='kv', secret_path='path1')
        # print(secret)

        # # secret_unwrap = vault_cluster.unwrap_secret(wrapping_token='')
        # # print(secret_unwrap)

        # secret_create = vault_cluster.create_secret(token=app_token, engine_name='kv', secret_path='path1', secret_data={'key1': 'v1'})
        # print(secret_create)

        # secret_update = vault_cluster.update_secret(token=app_token, engine_name='kv', secret_path='path1', secret_data={'key1': 'v2'})
        # print(secret_update)

        # secret_delete = vault_cluster.delete_secret(token=app_token, engine_name='kv', secret_path='path1')
        # print(secret_delete)

        # secret_undelete = vault_cluster.undelete_secret(token=app_token, engine_name='kv', secret_path='path1', versions=[1])
        # print(secret_undelete)

        # secret_destroy = vault_cluster.destroy_secret(token=app_token, engine_name='kv', secret_path='path1', versions=[0])
        # print(secret_destroy)

        # secrets_destroy = vault_cluster.destroy_secrets(token=app_token, engine_name='kv', secret_path='path1')
        # print(secrets_destroy)



        #-------------------------------#
        # Demo Usage
        #-------------------------------#
        ldap_token = ''

        policies_to_create = {
            'kv-snowflake-full': {'path': 'kv/snowflake/*', 'cp': ["create", "read", "update", "patch", "delete", "list"]},
            'kv-snowflake-ro': {'path': 'kv/snowflake/*', 'cp': ["read", "list"]},
            'kv-snowflake-RDR-ro': {'path': 'kv/snowflake/RDR_*', 'cp': ["read", "list"]},
        }
        for p, v in policies_to_create.items():
            policy_create = vault_cluster.create_policy(token=ldap_token, policy_name=p, secret_path=v['path'], capabilities=v['cp'])
            print(policy_create)

        roles_to_create = {
            'kv-snowflake-RDR-ro': {'policies': ['kv-snowflake-RDR-ro']},
            'kv-snowflake-full': {'policies': ['kv-snowflake-full']},
        }
        for r, v in roles_to_create.items():
            role_create = vault_cluster.create_role(token=ldap_token, role_name=r, token_policies=v['policies'])
            print(role_create)

        roles = {}
        for r in roles_to_create.keys():
            role_id = vault_cluster.get_role_id(token=ldap_token, role_name=r)
            secret_id = vault_cluster.create_secret_id(token=ldap_token, role_name=r)
            app_token = vault_cluster.get_app_token(token=ldap_token, role_id=role_id, secrect_id=secret_id)
            roles[r] = {'role_id': role_id, 'secret_id': secret_id, 'app_token': app_token}
        print(roles)

        secret_to_create = {
            {'password': 'pwd'}: {'path': 'kv/snowflake/RDR_BEMFG_NPI_P', 'engine': 'kv', 'app_token': roles['kv-snowflake-full']['app_token']},
        }
        for d, v in secret_to_create.items():
            secret_create = vault_cluster.create_secret(token=v['app_token'], engine_name=v['engine'], secret_path=d['path'], secret_data=d)
            print(secret_create)

        secret_to_find = {
            'kv/snowflake/RDR_BEMFG_NPI_P': {'engine': 'kv', 'app_token': roles['kv-snowflake-RDR-ro']['app_token']},
        }
        secrets = []
        for s, v in secret_to_find.items():
            secret, version = vault_cluster.get_secret(token=v['app_token'], engine_name=v['engine'], secret_path=s)
            secrets[s] = {'secret': secret, 'version': version}
        print(secrets)

