FROM debian:bookworm-slim@sha256:60eac759739651111db372c07be67863818726f754804b8707c90979bda511df

RUN apt-get update \
    && apt-get install --yes --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd \
    && useradd --create-home --shell /bin/sh interop \
    && echo 'interop:correct-horse-battery-staple' | chpasswd \
    && ssh-keygen -A \
    && printf '%s\n' \
        'PasswordAuthentication yes' \
        'KbdInteractiveAuthentication no' \
        'UsePAM no' \
        'PermitRootLogin no' \
        'AllowUsers interop' \
        >> /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
