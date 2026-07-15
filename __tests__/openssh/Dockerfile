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
    && ssh-keygen -q -t dsa -N '' -f /etc/ssh/ssh_host_dsa_key \
    && printf 'modern-client.test ' > /etc/ssh/ssh_known_hosts \
    && cut -d ' ' -f 1,2 /etc/ssh/ssh_host_ed25519_key.pub >> /etc/ssh/ssh_known_hosts \
    && printf '%s\n' 'modern-client.test localuser' > /home/interop/.shosts \
    && chown interop:interop /home/interop/.shosts \
    && chmod 0600 /home/interop/.shosts \
    && printf '%s\n' 'Host *' '    EnableSSHKeysign yes' >> /etc/ssh/ssh_config \
    && sed -i 's/^KbdInteractiveAuthentication .*/KbdInteractiveAuthentication yes/' /etc/ssh/sshd_config \
    && printf '%s\n' \
        'PasswordAuthentication yes' \
        'KbdInteractiveAuthentication yes' \
        'GatewayPorts clientspecified' \
        'UsePAM yes' \
        'Banner /etc/modernssh-banner' \
        'Ciphers chacha20-poly1305@openssh.com,aes128-gcm@openssh.com,aes256-gcm@openssh.com,aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,aes192-cbc,aes256-cbc,3des-cbc' \
        'MACs hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com,hmac-sha1-etm@openssh.com,hmac-sha1-96-etm@openssh.com,hmac-sha2-256,hmac-sha2-512,hmac-sha1,hmac-sha1-96,hmac-md5-etm@openssh.com,hmac-md5-96-etm@openssh.com,hmac-md5,hmac-md5-96' \
        'KexAlgorithms +diffie-hellman-group-exchange-sha1,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1' \
        'HostKeyAlgorithms +ssh-dss' \
        'PubkeyAcceptedAlgorithms +ssh-dss' \
        'HostbasedAuthentication yes' \
        'HostbasedUsesNameFromPacketOnly yes' \
        'IgnoreRhosts no' \
        'HostKey /etc/ssh/ssh_host_ed25519_key' \
        'HostKey /etc/ssh/ssh_host_rsa_key' \
        'HostKey /etc/ssh/ssh_host_ecdsa_key' \
        'HostKey /etc/ssh/ssh_host_ecdsa_384_key' \
        'HostKey /etc/ssh/ssh_host_ecdsa_521_key' \
        'HostKey /etc/ssh/ssh_host_dsa_key' \
        'PermitRootLogin no' \
        'AllowUsers interop' \
        >> /etc/ssh/sshd_config

COPY entrypoint.sh /usr/local/bin/modernssh-openssh-entrypoint
COPY http-response.sh /usr/local/bin/modernssh-http-response
RUN chmod 0755 /usr/local/bin/modernssh-openssh-entrypoint /usr/local/bin/modernssh-http-response

EXPOSE 22

CMD ["/usr/local/bin/modernssh-openssh-entrypoint"]
