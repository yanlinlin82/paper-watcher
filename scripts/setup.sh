#!/bin/bash

if [ "$1" == "-h" -o "$1" == "--help" ]; then
    echo "Usage: $0 [-h|--help] [-u|--upgrade]"
    echo "Setup or upgrade the environment"
    echo "Options:"
    echo "  --help         Show this help message and exit"
    echo "  -u, --upgrade  Upgrade the environment"
    exit 0
fi

#==========================================================#

if [ "$1" == "-u" -o "$1" == "--upgrade" ]; then
    echo "Upgrading dependencies"
    uv lock --upgrade
    uv sync --no-install-project
else
    echo "Syncing dependencies"
    uv sync --no-install-project
fi

#==========================================================#
echo "Setup done"
