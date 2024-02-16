import argparse
import ipaddress
import subprocess
import sys
import os

from jinja2 import Environment, FileSystemLoader

import openstack

PROVISION_STATE_AVAILABLE = "available"
PROVISION_STATE_ACTIVE = "active"
PRIVATE_NET_NAME = "net-okdci_hosts"
PRIVATE_SUBNET_NAME = "subnet-okdci_hosts"
CIR_TYPE = "test_host"


# This script list all of the baremetal/ironic nodes in a MOC project
# For each one it connects up the needed network/subnet and provisions the node
# A single floating is then used to expose port 22 and 8213
# port 22 on the node is mapped to port 1XXX on the floating ip (where x is the last octect of the nodes internel ip)
# port 8213 on the node is mapped to port 8XXX on the floating ip
# 3 properties are then set on the nodes extra data for ofcir
# ofcir_type: the cir type
# ofcir_ip: the floating ip
# ofcir_data["port_ssh"]: the FIP port for ssh
# ofcir_data["port_proxy"]: the FIP port for proxy

# We don't hanndle leases in this script, this was done manually before hand
# lease offers 
# openstack esi offer list
# Current leases
# openstack esi lease list
# Claim an offer with this command, barmetal nodes should then appear in "baremetal node list"  (is seems to be async so you might have to wait a little)
# openstack esi offer claim e176d645-6373-4cd6-8a81-28608168b0d

# Get a FIP, create if it doesn't already exist
def get_or_create_fip(conn, description):
    floating_ips = conn.network.ips(floating=True)
    for ip in floating_ips:
        if ip["description"] == description:
            break
    else:
        # TODO: find the ID of floating ip network "external"
        ip = conn.network.create_ip(floating_network_id="71bdf502-a09f-4f5f-aba2-203fe61189dc", description=description)
    return ip

# Iterates through baremetal nodes, setting their ofcir_type to host and then return the list
def get_nodes(conn):
    nodes = list(conn.baremetal.nodes(fields=["uuid", "name", "extra", "power_state", "provision_state"]))
    nodes_to_use = []
    for node in nodes:

        if node.extra.get("ofcir_cir") == "taken":
            print("Skipping node %s, its taken"% node["name"])
            continue

        if node.extra.get("ofcir_type") and node.extra.get("ofcir_type") != CIR_TYPE:
            print("Skipping node %s, its not our type"% node["name"])
            continue

        if node["provision_state"] not in [PROVISION_STATE_AVAILABLE, PROVISION_STATE_ACTIVE]:
            print("Skipping node %s, its not in the correct state"% node["name"])
            continue
        nodes_to_use.append(node)

    return nodes_to_use

# We need 3 networks/subnets for a env
# create them here, each subnet has specific properites that need to be set
def get_or_create_network(conn, name, create=True, network_name=None, subnet_name=None):
    if network_name == None:
        network_name = "net-"+name
    if subnet_name == None:
        subnet_name = "subnet-"+name

    net = subnet = None
    for n in conn.network.networks():
        if n["name"] == network_name:
            net=n

    for sn in conn.network.subnets():
        if sn["name"] == subnet_name:
            subnet=sn

    if create:
        if not net:
            net = conn.network.create_network(name=network_name, port_security_enabled=False)
        if not subnet:
            subnet = conn.network.create_subnet(name=subnet_name, network_id=net["id"], ip_version=4, cidr="192.168.123.0/24", dns_nameservers=["8.8.8.8"])
    return net, subnet


def add_interface_to_router(conn, router, subnet_id):
    try:
        conn.network.add_interface_to_router(router, subnet_id)
    except openstack.exceptions.BadRequestException as e:
        if "Router already has a port on subnet" not in e.details:
            raise

def runcmd(cmd: str) -> (str, int):
    exit_code = 0
    try:
        print("  ", cmd)
        output = subprocess.check_output(cmd, shell=True)
    except subprocess.CalledProcessError as e:
        output = e.output
        exit_code = e.returncode
    return output, exit_code

def detach_trunk(node, portid):
    return runcmd(f'openstack esi node network detach {node} {portid}')

def create_trunk(switch_port, native, tagged):
    tagged = "".join([f" --tagged-networks {t}" for t in tagged])
    return runcmd(f'openstack esi trunk create --native-network {native} {tagged} "{switch_port}"')

def deploy(node, trunk_port_name):
    return runcmd(f'metalsmith deploy --image centos-image  --ssh-public-key ~/.ssh/id_ed25519.pub --resource-class baremetal --candidate {node} --no-wait --port "{trunk_port_name}"')

# esi-switch1-tengigabitethernet 1/33-okd-trunk-port | a8:99:69:a7:0a:01 | ip_address='192.168.55.79', subnet_id='3b12cb59-dc2c-45d8-b178-a2992c566a5d'
def manage_trunk(conn, bmnode, bmport, netokd, trunk_ports):
    switch = bmport["local_link_connection"]["switch_info"]
    switch_port = bmport["local_link_connection"]["port_id"]

    trunk_name = f"{switch}-{switch_port}"
    trunk_port_name = f"esi-{switch}-{switch_port}-"+netokd["name"]+"-trunk-port"
    native = [netokd["provider:segmentation_id"]]

    print("setting up trunk ", trunk_port_name)
    trunk_port = trunk_ports.get(trunk_port_name)

    internal_info = bmport.get("internal_info")
    if internal_info:
        bmport_port = internal_info.get("tenant_vif_port_id")
        if bmport_port and trunk_port and bmport_port != trunk_port["id"]:
            print("Attached to the wrong port, detach")
            detach_trunk(bmnode["name"], trunk_port["id"])


    if not trunk_port:
        print("Creating ", trunk_port_name)
        create_trunk(trunk_name, PRIVATE_NET_NAME, [])
    return trunk_port_name


def main():
    # create a connection object
    conn = openstack.connect(cloud='openstack')

    nodes = get_nodes(conn)

    netokd, subnetokd = get_or_create_network(conn, PRIVATE_NET_NAME, True, PRIVATE_NET_NAME, PRIVATE_SUBNET_NAME)
    netext, subnetext = get_or_create_network(conn, "", False, network_name="external", subnet_name="subnet-external")

    for router in conn.network.routers():
        if router["name"] == "router-okdci":
            break
    else:
        router = conn.network.create_router(name="router-okdci", is_ha=False, external_gateway_info={'network_id': netext["id"]})

    add_interface_to_router(conn, router, subnet_id=subnetokd.id)

    bmports = conn.baremetal.ports(fields=["uuid", "address", "node_uuid", "local_link_connection", "internal_info"])
    bmports_by_node = {port["node_uuid"]: port for port in bmports}

    trunk_ports = {port["name"]: port for port in conn.network.ports() if port["name"]}

    fip = get_or_create_fip(conn, "okdci_hosts access")

    for i, bmnode in enumerate(nodes):
        bmport = bmports_by_node[bmnode["uuid"]]
        trunk_port_name = manage_trunk(conn, bmnode, bmport, netokd, trunk_ports)

        trunk_ports = {port["name"]: port for port in conn.network.ports() if port["name"]}
        ip = trunk_ports[trunk_port_name]["fixed_ips"][0]["ip_address"]
        offset = int(ip.split(".")[-1])
        sshport = str(1000+offset)
        proxyport = str(8000+offset)
        try:
            port_forwarding_rule = conn.network.create_port_forwarding(
                floatingip_id=fip["id"],
                internal_port_id=trunk_ports[trunk_port_name]["id"],
                internal_ip_address=trunk_ports[trunk_port_name]["fixed_ips"][0]["ip_address"],
                internal_port='22', external_port=sshport, protocol='tcp'
            )
        except openstack.exceptions.BadRequestException as e:
            if "A duplicate port forwarding" not in e.details:
                raise

        # create the port forwarding rule for ssh access to the provisioning node
        try:
            port_forwarding_rule = conn.network.create_port_forwarding(
                floatingip_id=fip["id"],
                internal_port_id=trunk_ports[trunk_port_name]["id"],
                internal_ip_address=trunk_ports[trunk_port_name]["fixed_ips"][0]["ip_address"],
                internal_port='8213', external_port=proxyport, protocol='tcp'
            )
        except openstack.exceptions.BadRequestException as e:
            if "A duplicate port forwarding" not in e.details:
                raise

    
        extra = bmnode.extra
        extra.update({"ofcir_type": CIR_TYPE, "ofcir_ip": fip.floating_ip_address, "ofcir_port_ssh": sshport, "ofcir_data":'{"ofcir_port_ssh":"%s", "ofcir_port_proxy":"%s"}'%(sshport, proxyport)})
        conn.baremetal.update_node(bmnode["uuid"], extra=extra)

        if bmnode["provision_state"] in [PROVISION_STATE_AVAILABLE]:
            deploy(bmnode["uuid"], trunk_port_name)


if __name__ == "__main__":
    main()
