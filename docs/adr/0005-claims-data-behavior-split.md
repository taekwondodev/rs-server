# Claims data and crypto logic split across crates

`domain-auth::claims` holds `AccessTokenClaims`/`RefreshTokenClaims` as plain data (fields,
`new()`, getters) with zero crypto dependencies; `infra-jwt::crypto::JwtCrypto` owns all
encode/decode/HKDF/PEM logic as inherent methods operating on those public fields, rather than
methods on the claim structs themselves. This keeps `domain-auth` free of `jsonwebtoken`/crypto
deps, and means adding a claim field never requires touching `infra-jwt` unless the new field also
changes validation rules.
