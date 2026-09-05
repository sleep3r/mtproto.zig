ARG BASE_IMAGE=debian:12
FROM ${BASE_IMAGE}

ENV container=docker
ENV DEBIAN_FRONTEND=noninteractive
ENV LANG=C.UTF-8
ENV LC_ALL=C.UTF-8

RUN set -eux; \
    # The CDN returns 404 for some Bullseye security package URLs with encoded '+'.
    # Use Debian's security endpoint; keep package signature verification enabled.
    if [ -f /etc/apt/sources.list ]; then \
        sed -i 's|http://deb.debian.org/debian-security|http://security.debian.org/debian-security|g' /etc/apt/sources.list; \
    fi; \
    apt-get update; \
    apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        dbus \
        iproute2 \
        procps \
        python3 \
        systemd \
        systemd-sysv; \
    apt-get clean; \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

STOPSIGNAL SIGRTMIN+3
VOLUME ["/sys/fs/cgroup"]
CMD ["/sbin/init"]
