FROM debian:10.6

RUN apt-get update -y
RUN apt-get install bison build-essential byacc file flex git golang libgmp3-dev wget -y
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
RUN tar -xzvf ./pbc-0.5.14.tar.gz

WORKDIR ./pbc-0.5.14
RUN ./configure
RUN make
RUN make install

RUN go get -u -d github.com/Nik-U/pbc

RUN ldconfig -v

RUN mkdir /apsi
COPY main.go /apsi/
