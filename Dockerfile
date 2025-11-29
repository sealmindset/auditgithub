FROM --platform=linux/amd64 python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    npm \
    openjdk-21-jre-headless \
    golang-go \
    ruby \
    ruby-dev \
    build-essential \
    wget \
    curl \
    unzip \
    ca-certificates \
    libpq-dev \
    cloc \
    && rm -rf /var/lib/apt/lists/*

# Install Node.js tools
RUN npm install -g retire pnpm yarn

# Install Ruby gems
RUN gem install bundler-audit

# Install Go tools
RUN go install golang.org/x/vuln/cmd/govulncheck@latest
ENV PATH="${PATH}:/root/go/bin"

# Install OWASP Dependency-Check
ENV DEPENDENCY_CHECK_VERSION=12.1.0
ENV DEPENDENCY_CHECK_URL=https://github.com/jeremylong/DependencyCheck/releases/download/v${DEPENDENCY_CHECK_VERSION}/dependency-check-${DEPENDENCY_CHECK_VERSION}-release.zip

# Download and install Dependency-Check
RUN echo "Downloading OWASP Dependency-Check ${DEPENDENCY_CHECK_VERSION}..." && \
    wget --no-check-certificate -q ${DEPENDENCY_CHECK_URL} -O /tmp/dependency-check.zip && \
    unzip -q /tmp/dependency-check.zip -d /opt/ && \
    rm /tmp/dependency-check.zip && \
    chmod +x /opt/dependency-check/bin/* && \
    echo "Dependency-Check installed successfully" && \
    /opt/dependency-check/bin/dependency-check.sh --version

ENV PATH="${PATH}:/opt/dependency-check/bin"

# Configure git to use the token for authentication
ARG GITHUB_TOKEN
RUN git config --global credential.helper store && \
    echo "https://${GITHUB_TOKEN}:x-oauth-basic@github.com" > /root/.git-credentials && \
    chmod 600 /root/.git-credentials

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt psycopg2-binary

# Create virtual environments for Python security tools to avoid dependency conflicts
RUN python -m venv /opt/venv/semgrep && \
    /opt/venv/semgrep/bin/pip install --no-cache-dir semgrep && \
    rm -f /usr/local/bin/semgrep && \
    ln -s /opt/venv/semgrep/bin/semgrep /usr/local/bin/semgrep

RUN python -m venv /opt/venv/bandit && \
    /opt/venv/bandit/bin/pip install --no-cache-dir bandit && \
    rm -f /usr/local/bin/bandit && \
    ln -s /opt/venv/bandit/bin/bandit /usr/local/bin/bandit

RUN python -m venv /opt/venv/checkov && \
    /opt/venv/checkov/bin/pip install --no-cache-dir checkov && \
    rm -f /usr/local/bin/checkov && \
    ln -s /opt/venv/checkov/bin/checkov /usr/local/bin/checkov

# Install Gitleaks
RUN curl -sSfL https://github.com/zricethezav/gitleaks/releases/download/v8.18.2/gitleaks_8.18.2_linux_x64.tar.gz -o gitleaks.tar.gz && \
    tar -xzf gitleaks.tar.gz && \
    mv gitleaks /usr/local/bin/ && \
    rm gitleaks.tar.gz

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Syft
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin

# Install Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Install CodeQL CLI
ENV CODEQL_VERSION=2.15.3
ENV CODEQL_HOME=/opt/codeql
RUN mkdir -p ${CODEQL_HOME} && \
    wget -q https://github.com/github/codeql-cli-binaries/releases/download/v${CODEQL_VERSION}/codeql-linux64.zip -O /tmp/codeql.zip && \
    unzip -q /tmp/codeql.zip -d ${CODEQL_HOME} && \
    rm /tmp/codeql.zip && \
    ln -s ${CODEQL_HOME}/codeql/codeql /usr/local/bin/codeql

# Pre-download CodeQL queries (standard packs)
RUN codeql pack download codeql/python-queries codeql/javascript-queries codeql/go-queries codeql/java-queries

# Install TruffleHog
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Install Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Install .NET SDK and OSSGadget
# Microsoft package signing key
RUN wget https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb -O packages-microsoft-prod.deb && \
    dpkg -i packages-microsoft-prod.deb && \
    rm packages-microsoft-prod.deb && \
    apt-get update && \
    apt-get install -y dotnet-sdk-8.0

# Install OSSGadget
RUN dotnet tool install --global Microsoft.CST.OSSGadget.CLI
ENV PATH="${PATH}:/root/.dotnet/tools"

# Copy the rest of the application
COPY . .

# Create a volume for reports
VOLUME ["/app/vulnerability_reports"]

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Entrypoint
ENTRYPOINT ["python", "scan_repos.py"]
