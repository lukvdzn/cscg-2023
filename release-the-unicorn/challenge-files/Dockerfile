FROM debian

ENV DEBIAN_FRONTEND=noninteractive

RUN set -x && \
    apt-get update && \
    apt-get install -y xinetd

RUN useradd -d /home/ctf/ -m -p ctf -s /bin/bash ctf
RUN echo "ctf:ctf" | chpasswd

WORKDIR /home/ctf

COPY ./unicorn unicorn
COPY flag .
COPY unicorn_svc /etc/xinetd.d/

RUN chmod +x unicorn

EXPOSE 1024

CMD xinetd -dontfork
