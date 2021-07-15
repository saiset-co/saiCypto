FROM ubuntu:18.04

WORKDIR /srv

RUN apt-get update -y
RUN apt-get install -y libglib2.0-dev
COPY docker/translations /srv/translations/
COPY docker/lib /srv/lib/
COPY docker/keys /srv/keys/
COPY docker/config.ini /srv/
COPY docker/admin.html /srv/
COPY docker/SaiCryptoModule /srv/

CMD ./SaiCryptoModule

EXPOSE 8080
