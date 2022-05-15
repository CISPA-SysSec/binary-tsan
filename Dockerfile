FROM ubuntu:20.04 as zipr
RUN DEBIAN_FRONTEND=noninteractive apt-get update &&   \
    DEBIAN_FRONTEND=noninteractive apt-get install -yq \
    git \
	postgresql  				\
	postgresql-client  			\
	libpqxx-dev				\
	sudo 					\
	nasm


RUN git clone --recurse-submodules https://git.zephyr-software.com/opensrc/zipr.git /opt/zipr
RUN cd /opt/zipr && bash -c ". set_env_vars && ./get-peasoup-packages.sh all && scons -j3"

RUN useradd -ms /bin/bash zuser && gpasswd -a zuser sudo 
RUN echo '%sudo   ALL=(ALL:ALL) NOPASSWD:ALL' >> /etc/sudoers
RUN echo 'export PATH=$PATH:/opt/ps_zipr/tools/' >> /home/zuser/.bashrc 
RUN echo 'sudo service postgresql start ' >> /home/zuser/.bashrc
RUN chown zuser:zuser /home/zuser/.bashrc
USER zuser
ENV USER=zuser
RUN sudo service postgresql start && cd /opt/zipr && (env USER=zuser ./postgres_setup.sh || true)




FROM zipr as btsan

USER root
ENV USER=root

RUN set -xe; \
	apt-get update; \
	DEBIAN_FRONTEND=noninteractive apt-get install --no-install-recommends -y \
		cmake g++ protobuf-compiler libprotobuf-dev; \
	apt-get update;

COPY . /opt/btsan

RUN cd /opt/btsan && mkdir build && cd build && cmake .. -DZIPR_LOCATION=/opt/zipr && make -j3




FROM zipr as parsec-benchmark


RUN set -xe; \
	sudo apt-get update; \
	DEBIAN_FRONTEND=noninteractive sudo apt-get install --no-install-recommends -y \
		cmake g++ unzip ca-certificates curl apt-transport-https gnupg git wget make m4 \
		libglib2.0-dev openssl libx11-dev libxext-dev libxt-dev libxmu-dev libxi-dev \
		libtbb-dev gettext libprotobuf-dev valgrind time; \
	sudo apt-get update;


RUN cd /home/zuser && wget http://parsec.cs.princeton.edu/download/3.0/parsec-3.0-core.tar.gz --no-check-certificate  && \
    tar xvzf parsec-3.0-core.tar.gz && rm parsec-3.0-core.tar.gz && \
    wget http://parsec.cs.princeton.edu/download/3.0/parsec-3.0-input-sim.tar.gz --no-check-certificate && \
    tar xvzf parsec-3.0-input-sim.tar.gz && rm parsec-3.0-input-sim.tar.gz;

COPY scripts/parsec_diff /home/zuser

RUN cd /home/zuser/parsec-3.0 && git init . && git apply /home/zuser/parsec_diff && ./env.sh && ./bin/parsecmgmt -a build -p blackscholes bodytrack facesim ferret fluidanimate freqmine raytrace swaptions vips;

RUN cd /home/zuser/parsec-3.0 && ./env.sh && ./bin/parsecmgmt -a build -c gcc-tsan -p blackscholes bodytrack facesim ferret fluidanimate freqmine swaptions vips;

COPY --from=btsan /opt/btsan /opt/btsan

WORKDIR /home/zuser

ENV USER=zuser

#CMD python3 /opt/btsan/scripts/parsec_benchmark.py /opt/btsan/build/thread-sanitizer.sh /home/zuser/parsec-3.0
