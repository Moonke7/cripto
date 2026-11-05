FROM debian:bookworm-slim

RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends openssh-server \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 1000 --shell /bin/bash --password '' marcos \
    && mkdir -p /run/sshd \
    && install -d -o marcos -g marcos -m 0700 /home/marcos/.ssh \
    && ssh-keygen -q -t ed25519 -N '' -f /etc/ssh/ssh_host_ed25519_key

COPY sshd_config /etc/ssh/sshd_config
COPY authorized_keys /home/marcos/.ssh/authorized_keys

RUN chown marcos:marcos /home/marcos/.ssh/authorized_keys \
    && chmod 0600 /home/marcos/.ssh/authorized_keys

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
