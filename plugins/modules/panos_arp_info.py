#!/usr/bin/python
# -*- coding: utf-8 -*-

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
    ip_only:
        description:
            - If set to true, an array of IPs will be returned
            - The default of false will result a dictionary with full information for each record
        type: bool
        default: false
        required: false
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
- name: Getting ARP details from all interfaces
    panos_arp_info:
        provider: '{{ provider }}'
    register: arp_int_full
- name: Getting ARP IPs from all interfaces
    panos_arp_info:
        provider: '{{ provider }}'
        ip_only: true
    register: arp_all_ip
- name: Getting ARP details from a specific interface
    panos_arp_info:
        provider: '{{ provider }}'
        interface: 'ethernet1/1'
    register: arp_int_full
- name: Getting ARP IPs from a specific interface with status complete
    panos_arp_info:
        provider: '{{ provider }}'
        ip_only: true
        interface: 'ethernet1/1'
        status: 'complete'
    register: arp_int_ip
"""

RETURN = """
ansible_module_results_arp_ip_only:
    description: IP Address from ARP table.
    returned: When the ip_only attribute is set to true
    type: list
    sample:
        - "172.26.1.1"
        - "172.26.1.2"
ansible_module_results_arp_detail:
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
            sample: "c"
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
            "static": "s",
            "complete": "c",
            "expiring": "e",
            "incomplete": "i"
        }
        status = status_dict.get(status)

    return status


def main():
    helper = get_connection(
        with_classic_provider_spec=True,
        panorama_error="Panorama is not supported for this module.",
        argument_spec=dict(
            ip_only=dict(type='bool', required=False, default=False),
            interface=dict(type='str', required=False, default='all'),
            status=dict(type='str', required=False, choices=['static', 'complete', 'expiring', 'incomplete'])
        ),
    )

    module = AnsibleModule(
        argument_spec=helper.argument_spec,
        supports_check_mode=False,
        required_one_of=helper.required_one_of,
    )

    parent = helper.get_pandevice_parent(module)

    ip_only = module.params["ip_only"]
    interface = module.params["interface"]
    status = module.params["status"]

    api_str = "<show><arp><entry name='{0}'/></arp></show>".format(interface)

    try:
        arp_elements = parent.op(api_str, cmd_xml=False).findall("./result/entries/entry")
    except PanDeviceError as e:
        module.fail_json(msg="Failed to get ARP response: {0}".format(e))

    status = convert_arp_status(status)
    arp_entries = []
    for arp_element in arp_elements:

        arp_status = arp_element.find("./status").text.strip()
        if arp_status != status and status is not None:
            continue

        if ip_only:
            arp = arp_element.find("./ip").text
        else:
            arp = {
                "ip": arp_element.find("./ip").text,
                "mac": arp_element.find("./mac").text,
                "interface": arp_element.find("./interface").text,
                "port": arp_element.find("./port").text,
                "status": arp_element.find("./status").text.strip(),
                "ttl": int(arp_element.find("./ttl").text)
            }
        arp_entries.append(arp)

    module.exit_json(changed=False, results=arp_entries)


if __name__ == "__main__":
    main()
