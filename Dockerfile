FROM debian:10.6

# Install dependencies:
RUN apt-get update -y
RUN apt-get install bison build-essential byacc file flex git golang libgmp3-dev wget -y

# Install the PBC library as a shared library in the VM:
RUN wget https://crypto.stanford.edu/pbc/files/pbc-0.5.14.tar.gz
RUN tar -xzvf ./pbc-0.5.14.tar.gz
WORKDIR ./pbc-0.5.14
RUN ./configure
RUN make
RUN make install

# ldconfig is needed to update the linker config so that it can find shared
# objects installed by the PBC installation scripts:
RUN ldconfig -v

# Download the Go wrapper around the PBC library:
RUN go get -u -d github.com/Nik-U/pbc

# Copy the main.go file to the /apsi directory:
RUN mkdir /apsi
COPY main.go /apsi/
