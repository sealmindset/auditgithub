FROM python:3.12-slim

WORKDIR /app

# Trust corporate TLS-inspection root CAs (e.g. Zscaler) so pip can reach PyPI from
# behind the proxy. Without this the build fails at `pip install` with
# CERTIFICATE_VERIFY_FAILED. The tempting fix — --trusted-host — turns verification
# off for the whole install, so a proxy that can already read the traffic could also
# alter the packages; trusting the CA keeps verification on. Same intent as
# Dockerfile.api, but the certs live outside this build context, so compose passes
# them in as the named context `corp_certs` (see docker-compose.yml). Where no
# interception is in play certs/ is empty and this copies nothing.
COPY --from=corp_certs / /usr/local/share/ca-certificates/extra/
RUN update-ca-certificates
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . ./mock_oidc/

EXPOSE 10090

CMD ["uvicorn", "mock_oidc.main:app", "--host", "0.0.0.0", "--port", "10090"]
