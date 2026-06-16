---
title: "Confirmation Response Parameter for OAuth 2.0 Token Exchange"
abbrev: "Token Exchange cnf"
category: std
ipr: trust200902

docname: draft-mcguinness-oauth-token-exchange-cnf-latest
submissiontype: IETF
consensus: true
v: 3
area: "Security"
workgroup: "Web Authorization Protocol"
keyword:
 - oauth
 - token exchange
 - confirmation
 - dpop
 - mtls
 - proof of possession
venue:
  group: "Web Authorization Protocol"
  type: "Working Group"
  mail: "oauth@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/oauth/"

author:
 -
    fullname: "Karl McGuinness"
    initials: "K."
    surname: "McGuinness"
    organization: "Independent"
    email: "public@karlmcguinness.com"

normative:
  RFC6749:
  RFC7638:
  RFC7800:
  RFC8414:
  RFC8693:
  RFC8705:
  RFC9449:
  IANA.oauth-parameters:

informative:
  I-D.ietf-oauth-identity-assertion-authz-grant:

---

--- abstract

This specification defines a `cnf` response parameter for the OAuth 2.0
Token Exchange {{RFC8693}} response. The parameter carries the
confirmation method that the authorization server applied to the issued
token, enabling clients to verify that sender-constraint binding (for
example a DPoP key or mutual-TLS client certificate) was performed
without inspecting the issued token. This is useful for opaque tokens,
encrypted tokens, or any other case where the client cannot read the
issued token's `cnf` claim directly.

--- middle

# Introduction

OAuth 2.0 Token Exchange {{RFC8693}} defines a protocol for exchanging
one security token for another. The Token Exchange request can convey
inputs that trigger the authorization server to issue a
sender-constrained token: a DPoP proof {{RFC9449}} in the request
header, a mutual-TLS client certificate {{RFC8705}}, or a future
sender-constraint method.

When the authorization server applies sender-constraining to the issued
token, today's primary signal to the client is the `cnf` claim
({{RFC7800}}) inside the issued token. For JWT-formatted tokens that
the client can introspect, this works. The signal fails in three
deployment shapes:

1. **Opaque tokens.** The issued token is an unstructured string and
   the client cannot read any claim from it.

2. **Encrypted tokens.** The issued token is a JWE encrypted to a
   downstream consumer (such as a Resource Authorization Server), and
   the client does not hold the decryption key.

3. **`token_type` is "N_A".** {{Section 2.2.1 of RFC8693}} requires the
   `token_type` response parameter to be `N_A` when the issued token
   is not used directly as an access token. Existing sender-constraint
   methods, such as DPoP {{RFC9449}}, rely on `token_type` carrying
   the binding method (`token_type: "DPoP"`) and that signal is
   unavailable here.

Without a protocol-level signal in the Token Exchange response, an
authorization server that silently fails to apply sender-constraining
(by error or by misbehavior) can downgrade the issued token without
the client noticing.

This document closes the gap by adding an optional `cnf` parameter to
the Token Exchange response. The parameter carries the same
Confirmation structure defined in {{RFC7800}} for the `cnf` claim. The
client verifies the response `cnf` against the key or certificate it
provided in the request, the same way it would verify the in-token
`cnf` claim, and treats absence (when sender-constraining was
expected) as a downgrade.


# Conventions and Definitions

{::boilerplate bcp14-tagged}

This document uses the terms "access token," "authorization server,"
"client," "resource server," "token endpoint," and "token response"
defined by OAuth 2.0 {{RFC6749}} and the terms "subject token,"
"actor token," "issued token type," and "token type identifier"
defined by OAuth 2.0 Token Exchange {{RFC8693}}.

This document uses the term "confirmation method" as defined in
{{RFC7800}} to refer to any of the sender-constraint binding
mechanisms recognized by the `cnf` claim, including the JWK
Thumbprint Confirmation Method (`jkt`) defined in {{RFC9449}} and
the X.509 Certificate Thumbprint Confirmation Method (`x5t#S256`)
defined in {{RFC8705}}.


# Confirmation Response Parameter {#cnf-response-parameter}

This specification adds the following optional parameter to the
Token Exchange response defined in {{Section 2.2 of RFC8693}}:

`cnf`:
: OPTIONAL. A JSON object containing one or more confirmation
  members as defined in {{Section 3 of RFC7800}}. The value
  identifies the confirmation method that the authorization server
  applied to the issued token, allowing the client to verify the
  sender-constraint binding without inspecting the issued token.

The structure and member names of the `cnf` response parameter are
identical to those of the `cnf` JWT claim defined in {{RFC7800}}.
Implementations supporting this specification reuse the same member
definitions and registry without introducing new confirmation
methods.


## Relationship to the In-Token `cnf` Claim {#cnf-comparison}

When the issued token is a JWT and carries a `cnf` claim, the `cnf`
response parameter MUST represent the same confirmation as that
claim: it MUST contain the same confirmation member name(s) with
values that identify the same key or certificate. The response
parameter does not replace the in-token claim; both are present so
the client can verify the binding without introspection and the
resource server (or other downstream consumer) can validate the
binding from the token itself.

Whenever this document requires two `cnf` values to be compared (for
example a response `cnf` against an in-token `cnf` claim, or a
response `cnf` against the client's sender-constraint input), they
are compared by confirmation method and value, not by byte
representation. JSON member ordering and insignificant whitespace do
not affect the comparison, and a thumbprint member (for example
`jkt` or `x5t#S256`) is compared as the base64url-encoded string it
represents. This avoids a dependency on any particular JSON
canonicalization scheme.

When the issued token is opaque or otherwise unreadable by the
client (for example because it is encrypted to a downstream
audience), the response parameter is the only signal available to
the client. The token's binding is still enforced when the token is
presented to its consumer.


# Authorization Server Behavior {#as-behavior}

An authorization server that supports this specification MUST follow
the rules in this section.

When the authorization server applies sender-constraining to the
token it issues in response to a Token Exchange request, it MUST
include the `cnf` parameter in the Token Exchange response. The
member names and values MUST identify the confirmation method
actually applied to the issued token.

When the authorization server does not apply sender-constraining to
the issued token, it MUST NOT include the `cnf` parameter in the
response. Inclusion of `cnf` without an applied binding would mislead
the client into believing the token is sender-constrained when it is
not.

When the authorization server receives a sender-constraint input in
the Token Exchange request (for example a DPoP proof header or a
mutual-TLS client certificate) and chooses not to apply the binding
to the issued token, it SHOULD reject the request with an error
response as defined in {{Section 2.2.2 of RFC8693}} (which uses the
error codes of {{Section 5.2 of RFC6749}}, for example
`invalid_request`) rather than issue an unbound token. If it does
issue an unbound token, the absence of `cnf` in the response signals
the downgrade to the client.


# Client Behavior {#client-behavior}

A client that supports this specification and provides
sender-constraint input in a Token Exchange request (for example a
DPoP proof or a mutual-TLS client certificate) MUST validate the
`cnf` parameter in the Token Exchange response as follows:

1. If the response contains a `cnf` parameter, the client MUST verify
   that the confirmation method and value match the
   sender-constraint input it provided. For example, if the client
   provided a DPoP proof, it MUST verify that `cnf` contains a `jkt`
   member whose value equals the JWK SHA-256 Thumbprint
   ({{RFC7638}}) of the public key in the DPoP proof JWT.

2. If the response does not contain a `cnf` parameter, the client
   MUST treat the response as if the issued token is not
   sender-constrained. If the client requires sender-constraining,
   it MUST reject the response and not use the issued token. Absence
   of `cnf` when sender-constraining was requested is a downgrade
   attempt by the authorization server (intentional or otherwise).

3. If the response contains a `cnf` parameter whose confirmation
   method does not match what the client provided (for example a
   `x5t#S256` value when the client provided a DPoP proof), the
   client MUST reject the response.

A client that did not provide sender-constraint input in the
request, but receives a response containing `cnf`, MAY use the issued
token. The presence of `cnf` informs the client that the token is
sender-constrained, and the client SHOULD honor the constraint when
presenting the token (for example by including a DPoP proof when
calling a resource server).


# Examples {#examples}

The examples in this section illustrate the `cnf` response parameter
for different confirmation methods. Line breaks are introduced for
readability; the actual response is a single JSON object.

## DPoP-Bound Token

A client sends a Token Exchange request that includes a DPoP proof
header {{RFC9449}} and requests an Identity Assertion JWT
Authorization Grant (ID-JAG)
{{I-D.ietf-oauth-identity-assertion-authz-grant}} as the issued
token type. For an ID-JAG, `token_type` is `N_A`, so the client
cannot rely on `token_type` to learn the binding. The authorization
server applies the binding and includes `cnf` with a `jkt` member in
the response.

~~~http
POST /oauth2/token HTTP/1.1
Host: as.example
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&requested_token_type=urn:ietf:params:oauth:token-type:id-jag
&audience=https://ras.example/
&subject_token=eyJraWQiOiJzMTZ0cVNtODhwREo4VGZCXzdrSEtQ...
&subject_token_type=urn:ietf:params:oauth:token-type:id_token
~~~

~~~http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store

{
  "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
  "access_token": "eyJ0eXAiOi...",
  "token_type": "N_A",
  "expires_in": 300,
  "cnf": {
    "jkt": "0ZcOCORZNYy-DWpqq30jZyJGHTN0d2HglBV3uiguA4I"
  }
}
~~~

The client compares the `jkt` value to the JWK SHA-256 Thumbprint of
the public key in the DPoP proof JWT. If they match, the binding is
confirmed; if not, the client rejects the response.

## Mutual-TLS-Bound Token

A client establishes a mutual-TLS connection to the token endpoint
and presents a client certificate. The authorization server applies
the binding and includes `cnf` with an `x5t#S256` member {{RFC8705}}
in the response.

~~~http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8

{
  "issued_token_type":
    "urn:ietf:params:oauth:token-type:access_token",
  "access_token": "mF_9.B5f-4.1JqM",
  "token_type": "Bearer",
  "expires_in": 3600,
  "cnf": {
    "x5t#S256": "bwcK0esc3ACC3DB2Y5_lESsXE8o9ltc05O89jdN-dg2"
  }
}
~~~

## No Sender-Constraint Applied

The client did not supply a DPoP proof or a mutual-TLS client
certificate. The authorization server issues an unbound token and
omits `cnf`.

~~~http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8

{
  "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
  "access_token": "eyJ0eXAiOi...",
  "token_type": "N_A",
  "expires_in": 300
}
~~~

A client that did not provide sender-constraint input is not
expected to find `cnf` in the response. A client that did provide
sender-constraint input but receives a response without `cnf` MUST
reject the response per {{client-behavior}}.


# Authorization Server Metadata {#as-metadata}

An authorization server that supports this specification SHOULD
include the following metadata parameter in its OAuth 2.0
Authorization Server Metadata {{RFC8414}}:

`token_exchange_cnf_response_supported`:
: OPTIONAL. Boolean value indicating whether the authorization
  server includes the `cnf` parameter in Token Exchange responses
  when it has applied sender-constraining to the issued token.
  Default is `false`.

This metadata lets a client distinguish an authorization server that
does not implement this specification (and therefore never emits
`cnf`) from one that implements it but did not apply
sender-constraining to a particular response. A client whose policy
requires sender-constraining can use this metadata to avoid
repeatedly sending requests to an authorization server that cannot
satisfy that policy. The metadata is an operational aid only; it
does not change the client validation rules of {{client-behavior}},
which fail closed on an absent `cnf` regardless of any advertised
support.


# Security Considerations {#security}

## The Response Parameter Is Informational

The `cnf` response parameter is informational for the client. The
authoritative enforcement of the sender-constraint binding occurs
when the issued token is presented to its consumer (a resource
server or another authorization server), which validates the token's
`cnf` claim against the sender-constraint proof provided in that
later request.

A client that successfully verifies the response `cnf` against its
expected key only knows that the authorization server did not
downgrade the issuance. It does not know that the consumer of the
token will enforce the binding correctly. Both checks are needed
end-to-end.

The check this parameter enables defends primarily against an
authorization server that fails to apply sender-constraining in
error or through misconfiguration, and against an on-path attacker
(addressed by TLS; see {{tls-for-the-response}}). It does not defend
against a malicious authorization server: such a server is the
issuer of the token, controls its contents entirely, and can equally
misreport its capabilities in the metadata of {{as-metadata}}.
Protection against a hostile issuer is out of scope for this
document.

## Absence Equals Unbound

The `cnf` response parameter MUST be present when the issued token
is sender-constrained and MUST be absent when it is not. A
zero-length, malformed, or partial `cnf` MUST be treated by the
client as if `cnf` were absent.

Clients MUST NOT treat the presence of `cnf` itself as proof of
binding without verifying the contents against the
sender-constraint input they provided.

## TLS for the Response {#tls-for-the-response}

The Token Exchange response is delivered over TLS per {{Section 4 of RFC8693}}.
Without TLS, an on-path attacker could strip or modify
the `cnf` parameter to suppress the binding signal. Implementations
MUST NOT operate the Token Exchange endpoint without TLS.

## Replay and Freshness

This specification does not by itself prevent replay of the response
`cnf` value across unrelated requests. The replay protection
mechanisms of the underlying sender-constraint method continue to
apply: DPoP relies on nonce and `jti` ({{RFC9449}}), mutual-TLS
relies on the live TLS session.

## Consistency with the In-Token `cnf`

If the response `cnf` parameter and the in-token `cnf` claim are
both present but do not represent the same confirmation (per the
comparison rules in {{cnf-comparison}}), the client MUST reject the
response. This prevents an authorization server from issuing a token
bound to one key while signaling a different key in the response,
intentionally or by error.

## Cross-Method Substitution

A client that provided a DPoP proof MUST reject a response whose
`cnf` carries a non-DPoP confirmation method (such as `x5t#S256`).
Cross-method substitution is a downgrade.

## Disclosure

The `cnf` response parameter discloses the binding method and the
key or certificate thumbprint to any party that observes the Token
Exchange response. Because the response is delivered over TLS to
the client that initiated the request, this disclosure is bounded
to the client. A thumbprint is a one-way hash of a public key or
certificate and does not by itself reveal additional personal data,
but it is a stable correlator for the bound key; authorization
servers SHOULD NOT include `cnf` in non-TLS-protected contexts.

## Minimizing Disclosed Key Material

For key-based confirmation methods, {{RFC7800}} permits the `cnf`
member to carry either a JWK SHA-256 Thumbprint (`jkt`, {{RFC7638}})
or a full public key as a `jwk` member. A thumbprint is sufficient
for the client to confirm the binding, because the client already
holds the corresponding public key from the sender-constraint input
it provided and can recompute the thumbprint.

Authorization servers SHOULD use a thumbprint confirmation method
(such as `jkt`) rather than embedding a full `jwk` member in the
`cnf` response parameter. A full `jwk` discloses more key material
than the client needs to verify the binding and unnecessarily
increases the size of the response.


# IANA Considerations {#iana}

## OAuth Parameters Registry

IANA is requested to register the following parameter in the "OAuth
Parameters" registry {{IANA.oauth-parameters}} established by
{{RFC6749}}:

* Parameter Name: `cnf`
* Parameter Usage Location: token response
* Change Controller: IETF
* Specification Document(s): {{cnf-response-parameter}} of this document


## OAuth Authorization Server Metadata Registry

IANA is requested to register the following metadata parameter in
the "OAuth Authorization Server Metadata" registry
{{IANA.oauth-parameters}}:

* Metadata Name: `token_exchange_cnf_response_supported`
* Metadata Description: Boolean indicating whether the authorization
  server includes a `cnf` parameter in Token Exchange responses for
  sender-constrained tokens
* Change Controller: IETF
* Specification Document(s): {{as-metadata}} of this document


--- back

# Acknowledgments
{:numbered="false"}

The gap addressed by this specification was identified during work on
"OAuth Identity Assertion Authorization Grant"
{{I-D.ietf-oauth-identity-assertion-authz-grant}}, where the
combination of `token_type: "N_A"` (mandated by {{RFC8693}}) and
optional ID-JAG encryption removed the existing client-side path for
detecting sender-constraint downgrade.


# Document History
{:numbered="false"}

{:aside}
> \[\[ To be removed from the final specification ]]

-00

* Initial draft.
