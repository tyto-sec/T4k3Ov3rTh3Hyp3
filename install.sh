#!/bin/sh
set -e

# Instala OpenSSH Server e utilitários básicos
apt-get update && \
apt-get install -y --no-install-recommends openssh-server ca-certificates && \
rm -rf /var/lib/apt/lists/*

## Instala Utilitários básicos
apt-get update && apt-get install -y wget git unzip curl && rm -rf /var/lib/apt/lists/*

# Instala Go 1.25.1
rm -rf /usr/local/go && wget https://go.dev/dl/go1.25.1.linux-amd64.tar.gz -O /tmp/go1.25.1.tar.gz && \
tar -C /usr/local -xzf /tmp/go1.25.1.tar.gz && \
rm /tmp/go1.25.1.tar.gz

# Configura variáveis de ambiente do Go
export GOROOT=/usr/local/go
export GOPATH=/root/go
export PATH=$PATH:$GOROOT/bin:$GOPATH/bin

# Adiciona ao profile para persistir
echo "export GOROOT=/usr/local/go" >> /etc/profile
echo "export GOPATH=/root/go" >> /etc/profile
echo "export PATH=\$PATH:\$GOROOT/bin:\$GOPATH/bin" >> /etc/profile

# Cria diretório GOPATH
mkdir -p $GOPATH

# Instala Python 3 e pip
apt-get update && apt-get install -y python3 python3-pip && rm -rf /var/lib/apt/lists/*

# Instala jq
apt-get update && apt-get install -y jq && rm -rf /var/lib/apt/lists/*


# Instala assetfinder
go install -v github.com/tomnomnom/assetfinder@latest
cp /root/go/bin/assetfinder /usr/local/bin/assetfinder

# Instala httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
cp /root/go/bin/httpx /usr/local/bin/httpx

# Instala subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
cp /root/go/bin/subfinder /usr/local/bin/subfinder

# Instala o anew
go install -v github.com/tomnomnom/anew@latest
cp /root/go/bin/anew /usr/local/bin/anew

# Instala o dnsx
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
cp /root/go/bin/dnsx /usr/local/bin/dnsx

# Instala amass
CGO_ENABLED=0 go install -v github.com/owasp-amass/amass/v5/cmd/amass@main
cp /root/go/bin/amass /usr/local/bin/amass

# Instala findomain
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux-i386.zip
unzip findomain-linux-i386.zip
chmod +x findomain
mv findomain /usr/bin/findomain
rm findomain-linux-i386.zip

# Instala o nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
cp /root/go/bin/nuclei /usr/local/bin/nuclei
nuclei -update-templates