FROM python:3.11-slim

RUN apt-get update && \
    apt-get install -y wget unzip curl git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN wget -q -O - https://api.github.com/repos/projectdiscovery/subfinder/releases/latest | grep "browser_download_url.*linux_amd64.zip" | cut -d '"' -f 4 | wget -qi - && \
    unzip subfinder_*_linux_amd64.zip -d /usr/local/bin && \
    rm subfinder_*_linux_amd64.zip

RUN wget -q -O - https://api.github.com/repos/projectdiscovery/dnsx/releases/latest | grep "browser_download_url.*linux_amd64.zip" | cut -d '"' -f 4 | wget -qi - && \
    unzip dnsx_*_linux_amd64.zip -d /usr/local/bin && \
    rm dnsx_*_linux_amd64.zip

RUN wget -q -O - https://api.github.com/repos/projectdiscovery/httpx/releases/latest | grep "browser_download_url.*linux_amd64.zip" | cut -d '"' -f 4 | wget -qi - && \
    unzip httpx_*_linux_amd64.zip -d /usr/local/bin && \
    rm httpx_*_linux_amd64.zip

RUN wget -q -O - https://api.github.com/repos/tomnomnom/anew/releases/latest | grep "browser_download_url.*linux_amd64.tar.gz" | cut -d '"' -f 4 | wget -qi - && \
    tar -xzf anew*linux_amd64.tar.gz -C /usr/local/bin && \
    rm anew*linux_amd64.tar.gz

RUN wget -q -O - https://api.github.com/repos/projectdiscovery/nuclei/releases/latest | grep "browser_download_url.*linux_amd64.zip" | cut -d '"' -f 4 | wget -qi - && \
    unzip nuclei_*_linux_amd64.zip -d /usr/local/bin && \
    rm nuclei_*_linux_amd64.zip

RUN nuclei -update-templates

WORKDIR /app

COPY takeover_scanner.py .

RUN chmod +x takeover_scanner.py

VOLUME ["/app/takeover_output"]

ENTRYPOINT ["python3", "takeover_scanner.py"]