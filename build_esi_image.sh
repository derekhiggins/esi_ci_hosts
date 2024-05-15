#!/bin/bash
set -eux

# Set the necessary variables
IMG=centos-stream-9
IMAGE_FILE="$IMG.qcow2"

# Make sure to use a version of DIB with
# https://github.com/openstack/diskimage-builder/commit/c03e46d9e1244d6ee2ac85ff119fed54b7e08c0e
DIB_RELEASE=9-stream disk-image-create centos vm dhcp-all-interfaces -o $IMG -p linux-firmware

# Remove existing images
openstack image delete $IMG || true

openstack image create --disk-format qcow2 --private --file $IMAGE_FILE $IMG

# Test the new image with
#ID=$(openstack image show -f value -c id $IMG)
#baremetal node set --instance-info image_source=$ID --instance-info kernel= --instance-info ramdisk= --instance-info image_disk_format=qcow2 <nodeuuid>
#baremetal node rebuild --config-drive '{"meta_data": {"public_keys": {"0": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFNa3NuKzEyjFTWgCzUMPlrc9/C0BjSU7MA0o4QjG4eZ derekh@laptop"}}}' <nodeuuid>
