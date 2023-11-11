FROM ubuntu:latest

RUN apt-get update \
    && apt-get install -y software-properties-common \
    && add-apt-repository ppa:ubuntu-toolchain-r/test \
    && apt-get update \
    && apt-get install -y gcc-13 g++-13 gcc-13-multilib g++-13-multilib \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 60 --slave /usr/bin/g++ g++ /usr/bin/g++-13

COPY . /

WORKDIR /

RUN gcc --version \
    && g++ -m32 -o chall vuln.c -fno-stack-protector -z execstack -z norelro -z relro -no-pie

CMD ["./chall"]
