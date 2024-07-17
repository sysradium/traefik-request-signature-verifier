FROM alpine:3
ADD . /plugins-local/src/github.com/sysradium/traefik-request-signature-verifier

FROM traefik:v2.11.6
COPY --from=0 /plugins-local /plugins-local
