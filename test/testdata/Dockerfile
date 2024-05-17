FROM debian:bookworm-slim

RUN apt update \
  && apt install -y bind9 procps

RUN mkdir -p /var/named/pki \
  && chown bind:bind /var/named \
  && chmod 700 /var/named/pki

COPY pki/server.pem pki/server-key.pem /var/named/pki/
RUN chown bind:bind /var/named/pki/*

COPY named.conf /etc/bind/named.conf

COPY example.my.nzzy.net.zone /var/named/example.my.nzzy.net.zone
RUN chown -R bind:bind /var/named/

EXPOSE 53/udp 53/tcp 853/tcp
CMD ["/usr/sbin/named", "-g", "-c", "/etc/bind/named.conf", "-u", "bind"]
