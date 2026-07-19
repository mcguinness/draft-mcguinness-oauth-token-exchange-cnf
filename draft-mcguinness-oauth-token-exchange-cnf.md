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
  RFC8693:
  RFC8705:
  RFC9449:
  IANA.oauth-parameters:

informative:
  I-D.ietf-oauth-identity-assertion-authz-grant:

---

--- abstract

This specification defines a `cnf` response parameter for the OAuth 2.0
Token Exchange (RFC 8693) response. The parameter carries the
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
token, the primary signal to the client is the `cnf` claim
({{RFC7800}}) inside the issued token. For JWT-formatted tokens the
client can read, this works. The signal fails in three deployment
shapes:

1. **Opaque tokens.** The issued token is an unstructured string and
   the client cannot read any claim from it.

2. **Encrypted tokens.** The issued token is a JWE encrypted to a
   downstream consumer (such as a Resource Authorization Server
   {{I-D.ietf-oauth-identity-assertion-authz-grant}}), and the client
   does not hold the decryption key.

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

{::boilerplate bcp14-tagged-bcp14}

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

The parameter's structure and member names are those of the `cnf`
JWT claim {{RFC7800}}, drawn from the IANA "JWT Confirmation
Methods" registry; this document defines no new confirmation
methods. Conveying a token's confirmation outside the token follows
the precedent of token introspection ({{Section 3.2 of RFC8705}};
{{Section 6.2 of RFC9449}}).

The parameter describes only the token in the `access_token`
response member (the issued token), not any `refresh_token` in the
same response. It is defined only for Token Exchange responses; its
use with other grant types is out of scope. Clients that do not
support this specification ignore unrecognized response members
({{Section 5.1 of RFC6749}}).


## Relationship to the In-Token `cnf` Claim {#cnf-comparison}

When the issued token is a JWT carrying a `cnf` claim, the `cnf`
response parameter MUST represent the same confirmation as that
claim: the same confirmation member name(s) identifying the same
key or certificate. The parameter does not replace the claim; the
client verifies the binding from the response while the token's
consumer validates it from the token itself. A client that can read
the issued token's `cnf` claim MUST reject the response if the two
values do not represent the same confirmation.

Wherever this document compares two `cnf` values (a response
parameter against an in-token claim, or against the client's
sender-constraint input), the comparison is by confirmation method
and value, not by byte representation:

* JSON member ordering and insignificant whitespace are ignored.

* A thumbprint member (for example `jkt` or `x5t#S256`) is compared
  as the base64url-encoded string it represents.

* A full public key in a `jwk` member is compared against a
  thumbprint by computing the key's JWK SHA-256 Thumbprint
  ({{RFC7638}}).

These rules avoid a dependency on any particular JSON
canonicalization scheme.


# Authorization Server Behavior {#as-behavior}

When the authorization server applies sender-constraining to the
token it issues in response to a Token Exchange request:

* It MUST include the `cnf` parameter in the Token Exchange
  response.

* The confirmation member name and value MUST identify the
  confirmation method actually applied to the issued token.

* The `cnf` parameter SHOULD contain exactly one confirmation
  member and MUST NOT contain a member identifying a binding that
  was not applied.

When the authorization server does not apply sender-constraining to
the issued token, it MUST NOT include the `cnf` parameter in the
response.

When the authorization server receives sender-constraint input (for
example a DPoP proof header or a mutual-TLS client certificate) but
does not apply the binding, it SHOULD reject the request with an
error response ({{Section 2.2.2 of RFC8693}}) rather than issue an
unbound token. If it issues the token anyway, omitting `cnf`
signals the downgrade to the client.


# Client Behavior {#client-behavior}

A client that provides sender-constraint input in a Token Exchange
request (for example a DPoP proof or a mutual-TLS client
certificate) MUST validate the Token Exchange response as follows:

1. If the response contains a `cnf` parameter, the client MUST
   verify that its confirmation method and value match the
   sender-constraint input:

   * For a DPoP proof: `cnf` MUST contain a `jkt` member whose
     value equals the JWK SHA-256 Thumbprint ({{RFC7638}}) of the
     public key in the DPoP proof JWT.

   * For a mutual-TLS client certificate: `cnf` MUST contain an
     `x5t#S256` member whose value equals the base64url-encoded
     SHA-256 hash of the certificate's DER encoding ({{RFC8705}}).

   If verification fails, including when `cnf` carries a different
   confirmation method than the input the client provided, the
   client MUST reject the response and not use the issued token.

2. The client MUST treat a `cnf` value that is not a JSON object,
   is an empty JSON object, or contains no confirmation member the
   client can verify as if `cnf` were absent.

3. If the response does not contain a `cnf` parameter, the client
   MUST treat the issued token as not sender-constrained. A client
   that requires sender-constraining MUST reject the response and
   not use the issued token.

4. If the `cnf` parameter contains more than one confirmation
   member, the client MUST apply the checks above to the member
   corresponding to its sender-constraint input and MUST ignore
   members whose confirmation method it does not recognize.

Absence of `cnf` indicates either a downgrade (intentional or
otherwise) or an authorization server that does not implement this
specification; the rules above treat both the same.

A client that did not provide sender-constraint input but receives
a response containing `cnf` holds a token bound to the identified
key or certificate. If the client holds that key or certificate
(for example, the certificate it used for mutual-TLS client
authentication), it MAY use the issued token and SHOULD satisfy the
confirmation method when presenting it. Otherwise the issued token
is unusable, and the client SHOULD treat the response as an error.


# Examples {#examples}

The examples in this section illustrate the `cnf` response parameter
for different confirmation methods. Extra line breaks in request
bodies and header fields are for display purposes only.

## DPoP-Bound Token

A client includes a DPoP proof header {{RFC9449}} in a Token
Exchange request for an Identity Assertion JWT Authorization Grant
(ID-JAG) {{I-D.ietf-oauth-identity-assertion-authz-grant}}. Because
`token_type` is `N_A` for an ID-JAG, it cannot signal the binding;
the authorization server instead includes `cnf` with a `jkt` member
in the response.

~~~http
POST /oauth2/token HTTP/1.1
Host: as.example
Content-Type: application/x-www-form-urlencoded
DPoP: eyJ0eXAiOiJkcG9wK2p3dCIsImFsZyI6IkVTMjU2IiwiandrIjp7...

grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange
&requested_token_type=
 urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid-jag
&audience=https%3A%2F%2Fras.example%2F
&subject_token=eyJraWQiOiJzMTZ0cVNtODhwREo4VGZCXzdrSEtQ...
&subject_token_type=
 urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aid_token
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

The client compares the `jkt` value to the JWK SHA-256 Thumbprint
of its DPoP public key and rejects the response on mismatch.

## Mutual-TLS-Bound Token

A client establishes a mutual-TLS connection to the token endpoint
and presents a client certificate. The authorization server applies
the binding and includes `cnf` with an `x5t#S256` member {{RFC8705}}
in the response.

~~~http
HTTP/1.1 200 OK
Content-Type: application/json;charset=UTF-8
Cache-Control: no-store

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
Cache-Control: no-store

{
  "issued_token_type": "urn:ietf:params:oauth:token-type:id-jag",
  "access_token": "eyJ0eXAiOi...",
  "token_type": "N_A",
  "expires_in": 300
}
~~~

A client that provided sender-constraint input treats this token as
unbound and, if it requires sender-constraining, rejects the
response ({{client-behavior}}).


# Security Considerations {#security}

## The Response Parameter Is Informational

The `cnf` response parameter is informational. Authoritative
enforcement of the binding occurs when the issued token is
presented to its consumer (a resource server or another
authorization server), which validates the token's `cnf` claim
against the presenter's proof. A verified response `cnf` tells the
client only that the authorization server did not downgrade
issuance, not that the token's consumer will enforce the binding;
both checks are needed end-to-end.

This check defends against an authorization server that fails to
apply sender-constraining through error or misconfiguration. It
does not defend against a malicious authorization server, which
issues the token and controls its contents entirely. Protection
against a hostile issuer is out of scope for this document.

## TLS for the Response {#tls-for-the-response}

TLS, already required for the token endpoint by
{{Section 3.2 of RFC6749}}, prevents an on-path attacker from
stripping or modifying the `cnf` parameter to suppress the binding
signal.

## Replay and Freshness

This specification does not itself prevent replay of the response
`cnf` value. The replay protections of the underlying
sender-constraint method continue to apply: the DPoP nonce and
`jti` ({{RFC9449}}) and, for mutual TLS, the live TLS session.

## Disclosure

The `cnf` response parameter discloses the binding method and a key
or certificate thumbprint only to the client that initiated the
request, which already holds the corresponding key material. A
thumbprint is a one-way hash and reveals no additional personal
data, though it is a stable correlator for the bound key.

Authorization servers SHOULD use a thumbprint member (such as
`jkt`) rather than a full `jwk` member: the client can recompute
the thumbprint from the key it already holds, so a full key
discloses more material than verification requires and enlarges the
response.


# IANA Considerations {#iana}

IANA is requested to register the following parameter in the "OAuth
Parameters" registry {{IANA.oauth-parameters}} established by
{{RFC6749}}:

* Parameter Name: `cnf`
* Parameter Usage Location: token response
* Change Controller: IETF
* Specification Document(s): {{cnf-response-parameter}} of this document


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
