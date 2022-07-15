#!/usr/bin/python
# -*- coding: utf-8 -*-

#  Copyright 2022 Palo Alto Networks, Inc
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from __future__ import absolute_import, division, print_function

__metaclass__ = type

DOCUMENTATION = """
---
module: panos_arp_info
short_description: Retrieve ARP table from PAN-OS.
description:
    - Retries ARP information objects on PAN-OS devices.
author:
    - Sean O'Brien (@undodelete)
version_added: '1.0.0'
requirements:
    - pan-python can be obtained from PyPI U(https://pypi.python.org/pypi/pan-python)
    - pandevice can be obtained from PyPI U(https://pypi.python.org/pypi/pandevice)
notes:
    - Panorama is not supported.
    - Check mode is not supported.
extends_documentation_fragment:
    - paloaltonetworks.panos.fragments.transitional_provider
options:
    interface:
        description:
            - The name of the interface to target a specific ARP table
            - The default is 'all', which will return all ARP tables
        type: str
        default: all
        required: false
    status:
        description:
            - The status of the ARP record target
            - The default doesn't apply any filter
        type: str
        required: false
        choices: ['static', 'complete', 'expiring', 'incomplete']
"""

EXAMPLES = """
- name: Getting ARP table
  panos_arp_info:
    provider: '{{ provider }}'
  register: arp_all

- name: Getting ARP table from a specific interface
  panos_arp_info:
    provider: '{{ provider }}'
    interface: 'ethernet1/1'
  register: arp_int

- name: Getting ARP table entries with status complete
  panos_arp_info:
    provider: '{{ provider }}'
    status: 'complete'
  register: arp_complete
"""

RETURN = """
ansible_module_results_arp_table:
    description: Network interface information.
    returned: When the ip_only attribute is set to true
    type: dict
    contains:
        ip:
            description: ARP IP address.
            type: str
            sample: "172.26.1.1"
        mac:
            description: ARP MAC address.
            type: str
            sample: "64:f6:9d:2e:17:0d"
        interface:
            description: ARP table interface.
            type: str
            sample: "ethernet1/1"
        port:
            description: ARP table port.
            type: str
            sample: "ethernet1/1"
        status:
            description: ARP record status.
            type: str
            sample: "  c  "
        ttl:
            description: ARP record time to live (Seconds).
            type: int
"""

from ansible.module_utils.basic import AnsibleModule
from ansible_collections.paloaltonetworks.panos.plugins.module_utils.panos import (
    get_connection,
)

try:
    from panos.errors import PanDeviceError
except ImportError:
    try:
        from panos.errors import PanDeviceError
    except ImportError:
        pass


def convert_arp_status(status):

    if status:
        status_dict = {
            "static": "  s  ",
            "complete": "  c  ",
            "expiring": "  e  ",
            "incomplete": "  i  "
        }
        status = status_dict.get(status)

    return status


def main():
    helper = get_connection(
        with_classic_provider_spec=True,
        argument_spec=dict(
            interface=dict(type='str', default='all'),
            status=dict(type='str', choices=['static', 'complete', 'expiring', 'incomplete'])
        ),
    )

    module = AnsibleModule(
        argument_spec=helper.argument_spec,
        supports_check_mode=True,
        required_one_of=helper.required_one_of,
    )

    parent = helper.get_pandevice_parent(module)

    interface = module.params["interface"]
    status = module.params["status"]

    api_str = "<show><arp><entry name='{0}'/></arp></show>".format(interface)
    try:
        entries = parent.op(api_str, cmd_xml=False).findall("./result/entries/entry")
    except PanDeviceError as e:
        module.fail_json(msg="Failed to get ARP response: {0}".format(e))

    status = convert_arp_status(status)
    arp_table = [
        {arp.tag: arp.text for arp in entry}
        for entry in entries if status == entry[0].text or status is None
    ]

    module.exit_json(changed=False, results=arp_table)


if __name__ == "__main__":
    main()
