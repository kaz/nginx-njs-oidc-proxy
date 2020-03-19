FROM alpine:edge

RUN apk add --no-cache --virtual .deps build-base pcre-dev zlib-dev openssl-dev && \
    cd /tmp && \
    mkdir nginx && \
    wget http://nginx.org/download/nginx-1.17.9.tar.gz -O - | tar zxf - --strip-components=1 -C nginx && \
    mkdir njs && \
    wget https://github.com/nginx/njs/archive/0.3.9.tar.gz -O - | tar zxf - --strip-components=1 -C njs && \
    cd nginx && \
    ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --conf-path=/etc/nginx/nginx.conf \
        --with-http_ssl_module \
        --add-module=../njs/nginx && \
    make && \
    make install && \
    rm -rf /tmp/* && \
    apk del --purge .deps && \
    apk add pcre zlib openssl

ENTRYPOINT ["nginx"]
CMD ["-g", "daemon off;"]
