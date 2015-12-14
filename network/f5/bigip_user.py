#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Matt Hite <mhite@hotmail.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

DOCUMENTATION = '''
---
module: bigip_user
short_description: "Manages F5 BIG-IP users"
description:
    - "Manages F5 BIG-IP users via iControl SOAP API"
version_added: "2.1"
author: "Matt Hite (@mhite)"
notes:
    - "Requires BIG-IP software version >= 11"
    - "F5 developed module 'bigsuds' required (see http://devcentral.f5.com)"
    - "Best run as a local_action in your playbook"
    - "password_credential is not an idempotent parameter and will always return changed == true"
    - "partition is not an idempotent parameter and will be ignored during an update operation"
    - "Multiple role:partition tuples are accepted in the partition_access argument but only the last is honored due to a BIG-IP bug (RFE 325269)."
    - "Actions performed on root user are unchartered territory, proceed at your own risk."
    - "When creating administrator accounts, set partition_access to 'administrator:[All]'"
requirements:
    - bigsuds
options:
    server:
        description:
            - BIG-IP API host
        required: true
    user:
        description:
            - BIG-IP API username
        required: true
    password:
        description:
            - BIG-IP API password
        required: true
    validate_certs:
        description:
            - If C(no), SSL certificates will not be validated. This should only be used
              on personally controlled sites using self-signed certificates.
        required: false
        default: 'yes'
        choices: ['yes', 'no']
    state:
        description:
            - User state
        required: true
        default: present
        choices: ['present', 'absent']
    partition:
        description:
            - Partition to create user. Ignored during updates.
        required: false
        default: 'Common'
    username_credential:
        description:
            - Username
        required: true
    full_name:
        description:
            - Full name of the user
        required: false
        default: None
    partition_access:
        description:
            - Scope authorization privileges to specified partitions. Should
              be in the form role:partition. Valid roles include administrator,
              traffic_manager, guest, asm_policy_editor, manager, editor,
              application_editor, certificate_manager, user_manager,
              resource_administrator, asm_editor, and advanced_operator.
              Partition portion of tuple should be an existing partition or
              the value '[All]'. Required during user creation.
        required: false
        default: None
    encrypted_password:
        description:
            - When true, indicates that the password_credential value passed
              to module has been encrypted using crypt. Defaults to False
              during user creation.
        required: false
        default: None
        choices: ['yes', 'no']
    password_credential:
        description:
            - Password string, either clear-text or encrypted with crypt
              (see 'encrypted_password' parameter). Required during user
              creation.
        required: false
        default: None
        choices: []
    shell:
        description:
            - Login shell. Valid shells are /bin/false, /bin/bash, and
              /usr/bin/tmsh. Required during user creation.
        required: false
        default: None
        choices: ['/bin/false', '/bin/bash', '/usr/bin/tmsh']
'''

EXAMPLES = '''

## playbook task examples:

---
# file bigip-test.yml
# ...
- hosts: bigip-test
  tasks:
  - name: Add user
    local_action: >
      bigip_user
      server=lb.mydomain.com
      user=admin
      password=mysecret
      state=present
      username_credential=joebob
      password_credential=supersecretpassword
      partition_access=administrator:[All]
      shell=/bin/bash

  - name: Update password
    local_action: >
      bigip_user
      server=lb.mydomain.com
      user=admin
      password=mysecret
      state=present
      username_credential=joebob
      password_credential=newsupersecretpassword

  - name: Delete user
    local_action: >
      bigip_user
      server=lb.mydomain.com
      user=admin
      password=mysecret
      state=absent
      username_credential=joebob
'''

# api helpers

def set_active_folder(api, folder):
    api.System.Session.set_active_folder(folder=folder)

def get_active_folder(api):
    return api.System.Session.get_active_folder()

def set_recursive_query_state(api, state):
    api.System.Session.set_recursive_query_state(state)

def get_recursive_query_state(api):
    return api.System.Session.get_recursive_query_state()

def enable_recursive_query_state(api):
    set_recursive_query_state(api, 'STATE_ENABLED')

def disable_recursive_query_state(api):
    set_recursive_query_state(api, 'STATE_DISABLED')

def start_transaction(api):
    api.System.Session.start_transaction()

def submit_transaction(api):
    api.System.Session.submit_transaction()

def user_exists(api, user):
    # need to switch to root, set recursive query state
    start_transaction(api)
    current_folder = get_active_folder(api)
    if current_folder != '/':
        set_active_folder(api, '/')
    current_query_state = get_recursive_query_state(api)
    if current_query_state == 'STATE_DISABLED':
        enable_recursive_query_state(api)
    result = False
    user_list = api.Management.UserManagement.get_list()
    if user_list:
        result = user in [x['name'] for x in user_list if 'name' in x]
    # set everything back
    if current_query_state == 'STATE_DISABLED':
        disable_recursive_query_state(api)
    if current_folder != '/':
        set_active_folder(api, current_folder)
    submit_transaction(api)
    return result

def delete_user(api, user):
    api.Management.UserManagement.delete_user(user_names=[user])

def set_password(api, user, password, encrypted_password=False):
    api.Management.UserManagement.change_password_2(user_names=[user],
        passwords=[{'is_encrypted': encrypted_password,
                    'password': password}])

def create_user(api, user, password, user_permissions, login_shell,
                full_name='', encrypted_password=False):
    user_id = {'name': user, 'full_name': full_name}
    password_info = {'is_encrypted': encrypted_password, 'password': password}
    user_info = {'user': user_id, 'password': password_info,
                 'permissions': user_permissions, 'login_shell': login_shell}
    api.Management.UserManagement.create_user_3(users=[user_info])

def get_fullname(api, user):
    full_name = api.Management.UserManagement.get_fullname(user_names=[user])[0]
    return full_name

def set_fullname(api, user, fullname):
    api.Management.UserManagement.set_fullname(user_names=[user], fullnames=[fullname])

def get_user_permission(api, user):
    permissions = api.Management.UserManagement.get_user_permission(user_names=[user])[0]
    return permissions

def set_user_permission(api, user, user_permissions):
    api.Management.UserManagement.set_user_permission(user_names=[user], permissions=[user_permissions])

def get_login_shell(api, user):
    login_shell = api.Management.UserManagement.get_login_shell(user_names=[user])[0]
    return login_shell

def set_login_shell(api, user, login_shell):
    api.Management.UserManagement.set_login_shell(user_names=[user], shells=[login_shell])


def main():
    argument_spec = f5_argument_spec()
    argument_spec['username_credential'] = {'type': 'str', 'required': True}
    argument_spec['password_credential'] = {'type': 'str'}
    argument_spec['partition_access'] = {'type': 'list'}
    argument_spec['shell'] = {'type': 'str', 'choices': ['/bin/false', '/bin/bash', '/usr/bin/tmsh']}
    argument_spec['encrypted_password'] = {'type': 'boolean'}
    argument_spec['full_name'] = {'type': 'str'}
    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)
    (server, user, password, state, partition, validate_certs) = f5_parse_arguments(module)
    username_credential = module.params['username_credential']
    password_credential = module.params['password_credential']
    partition_access = module.params['partition_access']
    login_shell = module.params['shell']
    encrypted_password = module.params['encrypted_password']
    full_name = module.params['full_name']

    # validate partition_access tuples if present
    valid_roles = ['administrator', 'traffic_manager', 'guest',
                   'asm_policy_editor', 'manager', 'editor',
                   'application_editor', 'certificate_manager',
                   'user_manager', 'resource_administrator',
                   'asm_editor', 'advanced_operator']
    user_permissions = []

    # create user_permissions data structure from partition_access
    if partition_access:
        for x in partition_access:
            if ':' in x:
                access_list = x.split(':')
                if len(access_list) != 2:
                    module.fail_json(msg='partition_access must be one or ' \
                                         'more role:partition tuples')
                elif access_list[0] not in valid_roles:
                    module.fail_json(msg='value of role must be one of: %s' % \
                                         ','.join(valid_roles))
                else:
                    access_list[0] = 'USER_ROLE_' + access_list[0].upper()
                    user_permissions.append({'role': access_list[0],
                                             'partition': access_list[1]})
            else:
                module.fail_json(msg='partition_access must be one or more '
                                     'role:partition tuples')

    try:
        result = {'changed': False}
        api = bigip_api(server, user, password)

        if state == 'absent':
            if user_exists(api, username_credential):
                result = {'changed': True, 'msg': 'User %s deleted' % username_credential}
                if not module.check_mode:
                    delete_user(api, username_credential)
            else:
                result = {'changed': False, 'msg': 'User %s does not exist' % username_credential}

        elif state == 'present':
            if not user_exists(api, username_credential):
                # sanity check parameters before creating the user
                missing_parameters = []
                if not password_credential:
                    missing_parameters.append('password_credential')
                if not partition_access:
                    missing_parameters.append('partition_access')
                if not login_shell:
                    missing_parameters.append('login_shell')
                if missing_parameters:
                    module.fail_json(msg='missing parameter(s) required for ' \
                                         'user creation: %s' % \
                                         ','.join(missing_parameters))
                else:
                    # set defaults
                    if encrypted_password is None:
                        encrypted_password = False
                    if full_name is None:
                        full_name = ''
                    # create the user
                    result = {'changed': True, 'msg': 'User %s created' % username_credential}
                    if not module.check_mode:
                        # save current folder so we can switch back
                        start_transaction(api)
                        current_folder = get_active_folder(api)
                        if current_folder != '/' + partition:
                            set_active_folder(api, '/' + partition)
                        create_user(api, username_credential,
                                    password_credential, user_permissions,
                                    login_shell, full_name, encrypted_password)
                        if current_folder != '/' + partition:
                            set_active_folder(api, current_folder)
                        submit_transaction(api)
            else:
                # user exists -- potentially modify attributes
                modified = []
                if full_name and get_fullname(api, username_credential) != full_name:
                    # update full name
                    modified.append('full_name')
                    result = {'changed': True}
                    if not module.check_mode:
                        set_fullname(api, username_credential, full_name)

                if user_permissions and get_user_permission(api, username_credential) != user_permissions:
                    # update user permissions
                    result = {'changed': True}
                    modified.append('partition_access')
                    if not module.check_mode:
                        set_user_permission(api, username_credential, user_permissions)

                if password_credential:
                    # update password can not be idempotently performed
                    if encrypted_password is None:
                        encrypted_password = False
                    modified.append('password_credential')
                    if not module.check_mode:
                        set_password(api, username_credential, password_credential, encrypted_password)

                if login_shell and get_login_shell(api, username_credential) != login_shell:
                    # update login shell
                    modified.append('shell')
                    if not module.check_mode:
                        set_login_shell(api, username_credential, login_shell)

                if modified:
                    # some attribute(s) were updated, generate appropriate result
                    result = {'changed': True, 'msg': 'Updated %s' % ','.join(modified)}
                else:
                    result = {'changed': False, 'msg': 'User %s exists, nothing to update' % username_credential}

    except Exception, e:
        module.fail_json(msg='received exception: %s' % e)

    module.exit_json(**result)

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.f5 import *
main()

