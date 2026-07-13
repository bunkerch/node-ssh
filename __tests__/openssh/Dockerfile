FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

RUN apt-get update \
    && apt-get install --yes --no-install-recommends openssh-server socat xauth \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && useradd --create-home --shell /bin/sh interop \
    && echo 'interop:correct-horse-battery-staple' | chpasswd \
    && printf '%s\n' 'OpenSSH authentication banner' > /etc/modernssh-banner \
    && ssh-keygen -A \
    && ssh-keygen -q -t ecdsa -b 384 -N '' -f /etc/ssh/ssh_host_ecdsa_384_key \
    && ssh-keygen -q -t ecdsa -b 521 -N '' -f /etc/ssh/ssh_host_ecdsa_521_key \
    && sed -i 's/^KbdInteractiveAuthentication .*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config \
    && printf '%s\n' \
        'PasswordAuthentication yes' \
        'KbdInteractiveAuthentication yes' \
        'GatewayPorts clientspecified' \
        'UsePAM yes' \
        'Banner /etc/modernssh-banner' \
        'HostKey /etc/ssh/ssh_host_ed25519_key' \
        'HostKey /etc/ssh/ssh_host_rsa_key' \
        'HostKey /etc/ssh/ssh_host_ecdsa_key' \
        'HostKey /etc/ssh/ssh_host_ecdsa_384_key' \
        'HostKey /etc/ssh/ssh_host_ecdsa_521_key' \
        'PermitRootLogin no' \
        'AllowUsers interop' \
        >> /etc/ssh/sshd_config

COPY entrypoint.sh /usr/local/bin/modernssh-openssh-entrypoint
RUN chmod 0755 /usr/local/bin/modernssh-openssh-entrypoint

EXPOSE 22

CMD ["/usr/local/bin/modernssh-openssh-entrypoint"]
