# Single JWT secret via HKDF, not two env vars

`JWT_SECRET_KEY` is the only auth secret in the environment; `infra-jwt` derives two independent
keys from it via HKDF — one for access-token EdDSA signing, one for refresh-token HS256 signing —
rather than requiring two separate secrets to configure and rotate.
