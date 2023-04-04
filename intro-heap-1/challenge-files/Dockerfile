FROM alpine:latest as builder

RUN apk update && apk add gcc make musl-dev gdb

RUN wget https://yx7.cc/code/ynetd/ynetd-0.1.2.tar.xz && \
    (echo "71c53f507b8fd75ef32bfebe4d476d1967a1332e  ynetd-0.1.2.tar.xz" | sha1sum -c) && \
    tar -xJf ynetd-0.1.2.tar.xz && cd ynetd-0.1.2 && CFLAGS="-static" make

FROM ubuntu@sha256:7a57c69fe1e9d5b97c5fe649849e79f2cfc3bf11d10bbd5218b4eb61716aebe6 as runner

RUN echo "8f7d59c6f95b0cf57a8db165033296dda91d1239  /lib/x86_64-linux-gnu/libc.so.6" | sha1sum -c

COPY --from=builder /ynetd-0.1.2/ynetd /ynetd

COPY ./main.c /main.c
COPY ./main /main
COPY ./flag /flag

CMD /ynetd -p 1024 /main
