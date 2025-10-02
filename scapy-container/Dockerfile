# Stage 1: Build TeX Live environment
FROM kalilinux/kali-rolling AS texlive-builder

RUN apt-get update && apt-get install -y \
    wget perl tar xz-utils fontconfig \
    && rm -rf /var/lib/apt/lists/*

# Install TeX Live using the network installer
COPY install-tl-unx.tar.gz /install-tl/install-tl-unx.tar.gz

RUN mkdir -p /install-tl && \
    cd /install-tl && \
    # https://mirror.ctan.org/systems/texlive/tlnet/install-tl-unx.tar.gz && \
    tar -xzf install-tl-unx.tar.gz && \
    cd install-tl-* && \
    echo "selected_scheme scheme-full" > texlive.profile && \
    echo "TEXDIR /usr/local/texlive" >> texlive.profile && \
    echo "TEXMFCONFIG ~/.texlive-config" >> texlive.profile && \
    echo "TEXMFVAR ~/.texlive-var" >> texlive.profile && \
    ./install-tl -profile texlive.profile

# Stage 1: Build Python 3.11 from Source
FROM kalilinux/kali-rolling AS python-builder

ENV DEBIAN_FRONTEND=noninteractive

# Install necessary build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    wget curl ca-certificates build-essential zlib1g-dev libncurses5-dev libgdbm-dev \
    libnss3-dev libssl-dev libreadline-dev libffi-dev libsqlite3-dev \
    libbz2-dev liblzma-dev tk-dev && \
    update-ca-certificates

# Download and compile Python 3.11 from source
RUN wget --no-check-certificate https://www.python.org/ftp/python/3.11.6/Python-3.11.6.tgz && \
    tar -xvf Python-3.11.6.tgz && \
    cd Python-3.11.6 && \
    ./configure --enable-optimizations && \
    make -j$(nproc) && \
    make altinstall && \
    cd .. && rm -rf Python-3.11.6 Python-3.11.6.tgz

# Install pip for Python 3.11
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.11 && \
    ln -s /usr/local/bin/pip3 /usr/bin/pip && \
    ln -s /usr/local/bin/pip3 /usr/bin/pip3.11

# Stage 2: Create a clean Kali image with only Python 3.11
FROM kalilinux/kali-rolling AS base

ENV DEBIAN_FRONTEND=noninteractive

# Install only runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl-dev libffi-dev libsqlite3-dev zlib1g-dev ca-certificates && \
    update-ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy compiled Python from builder stage
COPY --from=python-builder /usr/local/bin/python3.11 /usr/local/bin/python3.11
COPY --from=python-builder /usr/local/lib/libpython3.11* /usr/local/lib/
COPY --from=python-builder /usr/local/include/python3.11 /usr/local/include/python3.11
COPY --from=python-builder /usr/local/lib/python3.11 /usr/local/lib/python3.11
COPY --from=python-builder /usr/local/bin/pip3 /usr/local/bin/pip3
COPY --from=python-builder /usr/local/bin/pip /usr/local/bin/pip

# Set Python 3.11 as the default version
RUN ln -s /usr/local/bin/python3.11 /usr/bin/python && \
    ln -s /usr/local/bin/python3.11 /usr/bin/python3

# Verify Python installation
RUN python3 --version && python --version

# Copy TeX Live installation from the texlive-builder
COPY --from=texlive-builder /usr/local/texlive /usr/local/texlive
ENV PATH="/usr/local/texlive/bin/x86_64-linux:$PATH"
RUN latex --version && pdflatex --version

# Stage 3: Install scapy and dependencies
FROM base AS scapy-builder

RUN pip install --break-system-packages \
    scapy \
    matplotlib \
    pyx \
    vpython \
    cryptography

# Stage 4: Final build
#FROM base AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    tcpdump \
    tshark \
    net-tools \
    iputils-ping \
    graphviz \
    imagemagick \
    netbase \
    p0f \
    && rm -rf /var/lib/apt/lists/*

# Copy Python dependencies
#COPY --from=scapy-builder /usr/local/lib/python3.11/dist-packages /usr/local/lib/python3.11/dist-packages

VOLUME /workspace

WORKDIR /workspace
CMD ["/bin/bash", "-c", "scapy; exec bash"]
#ENTRYPOINT ["scapy"]
