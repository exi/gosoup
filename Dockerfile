FROM debian:jessie
MAINTAINER Reno Reckling <exi@wthack.de>

ADD ./gosoup /bin/gosoup

USER root

EXPOSE 8080

CMD ["/bin/gosoup"]
ENTRYPOINT ["/bin/gosoup"]
