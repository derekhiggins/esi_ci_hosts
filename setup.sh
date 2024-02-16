#!/bin/bash

# Create a Python virtual environment
python3 -m venv esienv

# Activate the virtual environment
source esienv/bin/activate

# Install the OpenStack client with Ironic
pip install python-openstackclient python-ironicclient python-esiclient metalsmith python-esileapclient Jinja2


