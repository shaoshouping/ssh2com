#!/bin/bash
SONIC_VERSION=$(sonic-cfggen -y /etc/sonic/sonic_version.yml -v build_version)
AC51_PLATFORM="x86_64-alibaba_ac51-48c2g-rj-r0"
platform_name=$(cat /host/machine.conf | grep onie_build_platform | awk -F= '{print $NF}')

set -ex

if [ "${platform_name}" == "$AC51_PLATFORM" ] && [ -f /usr/sbin/ssh2com ]; then
    /usr/sbin/ssh2com
fi

exit 0