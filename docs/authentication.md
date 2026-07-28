---
title: Authentication
description: Client credentials, server policy, prompts, banners, and multi-factor flows.
---

# User authentication

`modernssh` implements the RFC 4252 `none`, public-key, host-based, and password methods, RFC 4256
`keyboard-interactive` authentication, and RFC 4462 `gssapi-with-mic` and `gssapi-keyex`
authentication. The client uses the configured order, but only attempts methods that the server
advertises. When a factor
returns partial success, selection starts a new stage using the server's new continuation list;
this supports multi-factor policies without hard-coding a particular sequence.

Request usernames are strict UTF-8, while service and method identifiers use strict RFC 4250 SSH
names. Constructors copy caller-owned envelope metadata, unknown-method payloads are copied as
opaque bytes, and mutable text is revalidated during serialization.

During authentication, `authenticationMethodsRemaining` reflects the latest server continuation
list and `partialAuthenticationSuccess` indicates whether any factor has already succeeded.

Authentication and connection messages have disjoint protocol phases. Authentication packets are
accepted only after `ssh-userauth` service negotiation and before login completes; connection-layer
global requests and channel traffic are accepted only after successful authentication. A peer that
sends either class outside its phase receives an RFC protocol-error disconnect. Transport
diagnostics and key re-exchange remain valid independently of those higher-layer phases.

## Client authentication

Choose the allowed order with `authenticationMethodsOrder`. `none` is useful as the first entry
because it asks the server which methods may continue. It is never advertised by a server.

When no order is supplied, registering an awaited `keyboardInteractive` hook adds
`keyboard-interactive` to the default strategy immediately before password authentication. This
happens when `connect()` begins, so handlers may be installed after constructing the client. An
explicit `authenticationMethodsOrder` is a strict allow-list and is never broadened by hooks. The
constructor accepts mutable or readonly arrays and snapshots the configured order; later mutation
of the caller's array cannot change authentication behavior. Empty orders, duplicate entries, and
unsupported methods are rejected during construction. The resolved per-connection strategy does
not mutate the caller's configured array.

```ts
import { Client, SSHAuthenticationMethods } from "@bunkerch/modernssh"

const client = new Client({
    hostname: "ssh.example.com",
    username: "deploy",
    password: process.env.SSH_PASSWORD,
    authenticationMethodsOrder: [
        SSHAuthenticationMethods.None,
        SSHAuthenticationMethods.PublicKey,
        SSHAuthenticationMethods.Password,
        SSHAuthenticationMethods.KeyboardInteractive,
    ],
})
```

For adaptive selection, register the awaited `authenticationMethod` hook. Its controller begins
with the next choice from `authenticationMethodsOrder`, so a handler may leave it unchanged or
replace it with another configured method. The context contains immutable snapshots of methods
already attempted in this stage, the zero-based attempt number, the current username, and the
server's latest continuation list. After partial success, the attempted set is cleared and the hook
runs for the new stage. A replacement method must be configured and must appear in the continuation
list when one is known. The hook may deliberately retry a failed method with a different credential;
authentication stops after 32 total attempts. Set `decision.method` to `undefined` to stop earlier.
Every registered selector must complete without rejection; a contained selector failure stops
authentication instead of retaining the default or an earlier replacement.

```ts
client.hooker.hook("authenticationMethod", async (_hook, context, decision) => {
    if (context.methodsRemaining?.includes(SSHAuthenticationMethods.KeyboardInteractive)) {
        const available = await secondFactorDevice.isAvailable()
        if (available) decision.method = SSHAuthenticationMethods.KeyboardInteractive
    }
})
```

The selector may set `decision.username`, `decision.agent`, or `decision.hostbased` for only the
current attempt. A string agent value selects an agent socket; an `Agent` value may represent a
single key or a dynamic identity provider. The selected username becomes fixed after a server
reports partial success, preventing different factors from being combined across accounts.

```ts
client.hooker.hook("authenticationMethod", async (_hook, context, decision) => {
    const identity = await identityProvider.next(context.attempt)
    if (!identity) {
        decision.method = undefined
        return
    }

    decision.method = SSHAuthenticationMethods.PublicKey
    decision.username = identity.username
    decision.agent = identity.agent
})
```

Supply passwords and challenge responses through their dedicated awaited hooks. Password,
password-change, and keyboard-interactive values are used only when every handler for that request
completes without rejection. A later contained failure discards an earlier credential value before
it can be sent to the server. Credential, agent, GSS-API, and method-selection awaits are bound to
the current transport generation. If the same `Client` reconnects while an old provider is still
pending, that provider's eventual result is discarded before it can send an authentication packet
on the replacement connection.

Every authentication request and challenge response records its outbound packet sequence.
`SSH_MSG_UNIMPLEMENTED` is treated as rejection of an authentication exchange only when it names
that exact packet. It then advances or ends the configured method strategy like an ordinary method
failure. A rejection naming some other packet is ignored by that method and cannot displace the
eventual success, failure, challenge, or GSS-API response.

The server applies the same exact correlation while awaiting a signed retry after
`SSH_MSG_USERAUTH_PK_OK`, a changed password, a keyboard-interactive answer, or the next GSS-API
mechanism message. An exact rejection produces the advertised method failure immediately instead
of leaving authentication pending until its overall deadline. RFC 4462 diagnostic error and error
token messages are not waits: as required by that RFC, the server ignores any
`SSH_MSG_UNIMPLEMENTED` sent in response to those diagnostics.

The `password` client option installs the same awaited credential policy for a fixed value. An
explicit empty string is preserved and sent as an empty RFC 4252 password; omitting the option means
that no automatic password credential is configured. Configured password text is validated as
UTF-8 during construction. Applications should generally prefer a credential provider when a
password must be acquired or refreshed interactively.

Client construction also validates the username as UTF-8 and requires actual boolean values for
`agentForward`, `strictVendor`, `gssapiDelegateCredentials`, and
`gssapiKeyExchangeAuthentication`. JavaScript callers therefore cannot accidentally enable agent
forwarding or credential delegation with a truthy value such as the string `"false"`.

RFC 4252 banners are delivered independently of the active method:

```ts
client.on("banner", (message, languageTag) => {
    displayLoginNotice(message, languageTag)
})
```

Usernames, passwords, banners, password-change prompts, and every keyboard-interactive text field
use strict RFC UTF-8 decoding. Invalid UTF-8 is rejected before a value reaches an authentication
policy hook. Language tags are validated as RFC 3066 ASCII tags, including the permitted empty
tag. Packet constructors snapshot authentication envelopes, prompt objects, and response arrays;
later mutation of an input object cannot alter an in-flight authentication exchange. Password and
keyboard-interactive method constructors apply the same rule to credentials, language tags, and
submethod lists.

For a single identity, pass a loaded `PrivateKey`, encoded private-key string, or `Buffer` directly.
Encrypted input uses `passphrase`; the client parses it during construction and does not expose a
public configuration bag containing the encoded key or passphrase.

```ts
import { readFile } from "node:fs/promises"

const client = new Client({
    hostname: "ssh.example.com",
    username: "deploy",
    privateKey: await readFile("./id_ed25519"),
    passphrase: process.env.SSH_KEY_PASSPHRASE,
})
```

`privateKey` and `agent` are mutually exclusive. Use `PrivateKeyAgent` explicitly when several
already-loaded private keys should be attempted in order. It is non-interactive and signs entirely
in memory; unlike a socket-backed agent, it cannot be forwarded to the remote host.

Identity lists returned by an application-defined agent are validated and serialized into owned
public-key snapshots before authentication begins. Each signing operation gives the agent a copy of
the session-bound authentication preimage, then snapshots and locally verifies the returned
signature before any credential packet is sent. Agent mutation or an invalid signature therefore
cannot silently change the advertised identity or reach server authentication policy.

`agent` may also be a Unix-domain socket, Windows named pipe, or legacy Cygwin socket-descriptor
path for an RFC 9987 agent. The client normalizes a string through `createSocketAgent()` during
construction; omitting or passing an empty path does not implicitly enable `$SSH_AUTH_SOCK`. On
Windows, `agent: "pageant"` discovers Pageant 0.75 or newer through its protected per-user named
pipe after the application installs the optional `koffi` peer. Explicit Pageant pipe paths and all
other agents remain pure Node and do not load or require that package. See
[Socket agent authentication](getting-started.md#socket-agent-authentication) for explicit pipe
paths and discovery errors.

Keyboard-interactive may contain zero, one, or several prompts and may use several rounds. Supply
exactly one response per prompt. The `echo` flag tells a user interface whether an answer may be
displayed; mask the answer when the interface cannot honor the flag.

```ts
client.hooker.hook("keyboardInteractive", async (_hook, context, decision) => {
    decision.responses = await promptUser({
        title: context.name,
        instructions: context.instruction,
        prompts: context.prompts,
    })
})
```

An expired password arrives through the `passwordChange` hook. Leaving `newPassword` undefined
abandons password authentication and lets the client try another advertised method.

```ts
client.hooker.hook("passwordChange", async (_hook, context, decision) => {
    decision.newPassword = await requestNewPassword(context.prompt)
})
```

Do not log prompt responses, passwords, or replacement passwords. Password and keyboard-interactive
authentication should only be used over an authenticated, encrypted transport.

### GSS-API authentication

GSS-API support is mechanism-neutral. The library implements RFC 4462 negotiation, token exchange,
status messages, context completion, and the session-bound MIC; an application supplies one or more
mechanism adapters that perform the actual security-context operations. Each `oid` is the complete
canonical ASN.1 DER object-identifier encoding. `KERBEROS_V5_GSSAPI_OID` is provided for Kerberos V5
adapters.

```ts
import {
    Client,
    KERBEROS_V5_GSSAPI_OID,
    SSHAuthenticationMethods,
    type GSSAPIClientMechanism,
} from "@bunkerch/modernssh"

const kerberosMechanism: GSSAPIClientMechanism = {
    oid: KERBEROS_V5_GSSAPI_OID,
    async createContext(options) {
        const mechanismContext = await kerberosProvider.initiate({
            target: `host@${options.hostname}`,
            delegateCredentials: options.delegateCredentials,
        })
        return {
            step: (inputToken) => mechanismContext.step(inputToken),
            getMIC: (message) => mechanismContext.getMIC(message),
            close: () => mechanismContext.close(),
        }
    },
    async createKeyExchangeContext(options) {
        const mechanismContext = await kerberosProvider.initiate({
            target: `${options.service}@${options.hostname}`,
            delegateCredentials: options.delegateCredentials,
            anonymous: options.anonymous,
            mutualAuthentication: options.mutualAuthentication,
            integrity: options.integrity,
            replayDetection: options.replayDetection,
            sequenceDetection: options.sequenceDetection,
        })
        return {
            step: (inputToken) => mechanismContext.step(inputToken),
            verifyMIC: (message, mic) => mechanismContext.verifyMIC(message, mic),
            getMIC: (message) => mechanismContext.getMIC(message),
            close: () => mechanismContext.close(),
        }
    },
}

const client = new Client({
    hostname: "ssh.example.com",
    username: "deploy",
    gssapi: [kerberosMechanism],
    gssapiDelegateCredentials: false,
    authenticationMethodsOrder: [
        SSHAuthenticationMethods.GSSAPIWithMIC,
        SSHAuthenticationMethods.PublicKey,
    ],
})
```

An adapter may provide `createContext` for `gssapi-with-mic`, `createKeyExchangeContext` for
GSS-API key exchange, or both. At least one is required. These factories and `step`, `getMIC`,
`verifyMIC`, and `close` may return either direct values or promises. A
completed `step` must state whether per-message integrity is available. When it is available, the
client sends a MIC over the exact session identifier, username, service, and method fields. Without
integrity, it sends the RFC exchange-complete message instead. Any final output token is always sent
before that acknowledgement.

At most 64 adjacent SSH packets are retained while an asynchronous mechanism operation is pending.
Exceeding that bound closes the connection instead of allowing peer-controlled diagnostics or
out-of-order authentication traffic to grow an in-memory token queue without limit.

Providing `createKeyExchangeContext` also offers the RFC 8732 GSS-API key-exchange families for
that mechanism. Their SSH names are derived from the mechanism OID. Context establishment requests
mutual authentication and integrity while disabling replay and sequence detection, as required by
the protocol. The server's MIC authenticates the complete key-exchange transcript before the
client accepts the host key or installs transport keys.

For the initial exchange, the client normally requests a non-anonymous context and retains it long
enough to attempt RFC 4462 `gssapi-keyex` authentication. That authentication sends a MIC over the
session identifier, username, and requested service without establishing a second context. Set
`gssapiKeyExchangeAuthentication: false`, or omit `GSSAPIKeyExchange` from an explicit
`authenticationMethodsOrder`, when the mechanism context must be anonymous or must not be retained.
Contexts created during rekeying are never retained for user authentication.

An explicit order containing `GSSAPIKeyExchange` requires both an adapter with
`createKeyExchangeContext` and `gssapiKeyExchangeAuthentication` enabled. Contradictory
configuration is rejected during client construction rather than failing after transport setup.

Server adapters expose the authenticated mechanism identity and optional delegated credentials only
after context establishment and MIC verification. A key-exchange server context supplies `getMIC`
for the transport transcript and, if `gssapi-keyex` authentication is supported, `verifyMIC` plus a
completed step containing `peerIdentity`. Both authentication methods use the same awaited,
deny-by-default application decision:

```ts
const server = new Server({
    hostKeys,
    gssapi: [kerberosServerMechanism],
})

server.hooker.hook("gssapiAuthentication", async (_hook, context, decision) => {
    decision.allowLogin = await authorizeIdentity({
        username: context.username,
        peerIdentity: context.peerIdentity,
        delegatedCredentials: context.delegatedCredentials,
        integrity: context.integrity,
    })
})
```

Credential delegation is disabled by default and should be enabled only when the remote host is
trusted to act with the delegated identity. Mechanism contexts are closed after success, rejection,
abandonment, or failure. Throw `GSSAPIError` from an adapter to attach RFC major/minor status and an
optional mechanism error token. The client reports peer status through the synchronous
`gssapiError` or `gssapiKeyExchangeError` observation event; perform asynchronous follow-up outside
the EventEmitter handler.

RSA identities use RFC 8332 SHA-2 signatures by preference: `rsa-sha2-512`, then
`rsa-sha2-256`. The public key blob remains in the `ssh-rsa` format. When a server supplies the RFC
8308 `server-sig-algs` extension, the client restricts its attempts to the advertised signature
algorithms. Its value is decoded as a strict RFC 4251 name-list; malformed or non-ASCII
advertisements fail the connection instead of influencing signature selection through text
normalization. Direct private keys, `PrivateKeyAgent`, and `DiskAgent` select the requested hash
locally, while `SSHAgent` sends the corresponding RFC 9987 RSA SHA-2 flag to the external agent.
Ordinary and host-bound requests encode these identifiers with the shared RFC 4250 SSH-name codec;
malformed, non-ASCII, overlong, or comma-containing names are rejected before key policy.

ECDSA identities on `nistp256`, `nistp384`, and `nistp521` use the matching RFC 5656 algorithm name
and SHA-2 hash. Disk-backed OpenSSH ECDSA keys and delegated agent signatures use the same public-key
authentication path as Ed25519 and RSA identities. Public and private key parsers require the
curve identifier to match its algorithm as exact ASCII bytes; non-canonical key blobs are rejected
before authentication policy.

### Security-key identities

The public-key and certificate parsers accept the published FIDO/U2F identity formats
`sk-ssh-ed25519@openssh.com` and `sk-ecdsa-sha2-nistp256@openssh.com`. An `Agent` implementation may
return either identity from `getPublicKeys()` and provide its hardware-backed signature from
`sign()`; the normal public-key and host-bound authentication paths then preserve the signed flags
and counter. The server advertises these signature algorithms through `server-sig-algs`, including
the WebAuthn ECDSA signature form.

`EncodedSignature.data.securityKey` exposes the authenticator flags and counter. WebAuthn ECDSA
signatures additionally expose the origin, client-data wrapper, and extension bytes. Verification
checks the application hash, flags, counter, message challenge, origin prefix, extension-present
flag, and underlying Ed25519 or P-256 signature. Buffers are copied when parsed or constructed and
mutable metadata is revalidated before serialization or verification.

Cryptographic verification does not decide an application's authentication policy. In particular,
a security-key identity is still one authentication factor. A server that requires evidence such
as user presence must inspect the authenticated flags before allowing login:

```ts
server.hooker.hook("publicKeyAuthentication", async (_hook, context, decision) => {
    if (!context.signature) {
        decision.requestSignature = true
        return
    }

    const securityKey = context.signature.data.securityKey
    if (!securityKey || (securityKey.flags & 0x01) === 0) return
    if (!context.publicKey.verifySignature(context.signatureMessage, context.signature)) return

    decision.allowLogin = await authorizeSecurityKeyCounter({
        username: context.username,
        publicKey: context.publicKey,
        counter: securityKey.counter,
    })
})
```

The library parses public identities, certificates, signatures, and private containers containing
hardware key handles. It supports delegated signing through `Agent`, but it does not enroll
authenticators or communicate with them directly. Those operations belong in a FIDO provider used
by the application or receiving agent.

`SecurityKeyAttestation` parses the published `ssh-sk-attest-v00` and `ssh-sk-attest-v01`
enrollment records. Version 1 adds CBOR authenticator data; both versions contain an attestation
certificate, enrollment signature, reserved flags, and reserved bytes. The certificate,
signature, authenticator data, and reserved value remain opaque and are returned as defensive
copies, matching the format's storage role:

```ts
import { SecurityKeyAttestation } from "@bunkerch/modernssh"

const attestation = await SecurityKeyAttestation.load("./id_ed25519_sk.attestation")
await registerHardwareIdentity({
    certificate: attestation.certificate,
    signature: attestation.enrollmentSignature,
    authenticatorData: attestation.authenticatorData,
})
```

Parsing proves only that the record is well-formed. Applications must validate the attestation
certificate, enrollment signature, authenticator data, and local manufacturer policy before
treating a key as hardware-backed. Attestation data is not privacy-preserving and may identify a
token's manufacturer and batch, so retain or transmit it only for an explicit registration
workflow. Direct authenticator enrollment remains outside the library.

Historical RFC 4253 DSS identities are available as `ssh-dss` for explicitly configured legacy
peers. They use only DSA-1024 with SHA-1 and are excluded from normal algorithm offers. Do not
enable them for new credentials; prefer Ed25519, ECDSA, or RSA SHA-2.

When a server advertises `publickey-hostbound@openssh.com` version 0, public-key authentication
automatically uses the host-bound request. The signed message then contains the exact host-key blob
that completed key exchange, so a delegated signature cannot be replayed to another server. The
client accepts only the exact version-0 advertisement and otherwise uses RFC 4252 public-key
authentication.

Servers with a `publicKeyAuthentication` hook advertise host-bound authentication automatically.
The same awaited hook handles both forms: `context.hostbound` identifies the bound form and
`context.serverHostKey` is its parsed host key. The implementation rejects a request whose embedded
key differs from the key used for this connection before invoking policy. Applications must still
Signed requests are cryptographically verified before the hook runs. Applications authorize the
already-verified key and may use `context.signatureMessage` for auditing.

### Certificate identities

Pair a private key with its issued public certificate by passing both options. Encoded values and
parsed key objects are accepted:

```ts
const client = new Client({
    hostname: "ssh.example.com",
    username: "deploy",
    privateKey: await readFile("./id_ed25519"),
    certificate: await readFile("./id_ed25519-cert.pub"),
})
```

`PrivateKey.withCertificate(certificate)` provides the same pairing for `PrivateKeyAgent`.
`DiskAgent` automatically prefers `name-cert.pub` over `name.pub`, and delegated agents may return
certificate identities directly. The certificate stays separate from private-key serialization.
Malformed discovered public-key files are skipped and can be reported through the awaited
`onInvalidPublicKey` option.

Standard certificate key types are accepted when configured or supplied explicitly. This includes
Ed448 user identities: the request advertises `ssh-ed448-cert`, signs with the underlying
`ssh-ed448` algorithm, verifies possession before policy, and leaves CA and principal authorization
to the awaited hook. The active working-group names remain outside interoperable defaults until
they are registered. Standard certificates must contain at least one principal as required by the
working-group format; the older deployed certificate encoding retains its empty-principal parsing
semantics for compatibility, so policy must handle that case deliberately.

On the server, `context.certificate` contains the verified certificate when present. Before the
awaited policy hook runs, the library checks its CA signature, user role, validity interval, and
the request's possession signature. It also validates `source-address`, security-key
`verify-required` and `no-touch-required` assertions, and the shapes of recognized options and
extensions. The hook must still trust the CA explicitly and authorize at least one principal for
`context.username`.

Unknown critical options fail closed. An application may support a vendor critical option by fully
enforcing it in the awaited hook and then adding its exact name to
`decision.handledCertificateCriticalOptions`. Listing a name is an enforcement claim, not a request
to ignore the option:

```ts
server.hooker.hook("publicKeyAuthentication", async (_hook, context, decision) => {
    const certificate = context.certificate
    if (!certificate || !context.signature) {
        decision.requestSignature = certificate !== undefined
        return
    }

    const tenant = certificate.data.criticalOptions.find(
        (option) => option.name === "tenant@example.com",
    )
    if (tenant) {
        await requireTenantAccess(context.username, tenant.data)
        decision.handledCertificateCriticalOptions = ["tenant@example.com"]
    }

    decision.allowLogin = await trustCertificateAuthority(
        certificate.data.signatureKey,
        context.username,
        certificate.data.principals,
    )
})
```

Certificate permissions are deny-by-default. Agent forwarding, TCP forwarding, PTY allocation, and
X11 forwarding require their matching `permit-*` extension; denied requests are rejected before
their application policy hook. `force-command` replaces exec commands and routes shell and
subsystem requests through the awaited `execRequest` hook and the synchronous `exec` observation
event using the forced command. When certificate authentication is one factor of a multi-factor
login, restrictions from every accepted certificate are intersected. Conflicting forced commands
reject authentication.

Host-based authentication proves possession of a client machine's private host key and sends the
claimed client hostname and local username for authorization. Configure all three explicitly and
include `Hostbased` in the method order. The hostname must be a non-empty ASCII DNS name; a trailing
root dot is accepted. The server rejects non-ASCII hostname bytes before policy and reconstructs
the signature preimage only from fields whose wire encoding was validated without lossy text
conversion.

```ts
const client = new Client({
    hostname: "ssh.example.com",
    username: "deploy",
    hostbased: {
        key: clientHostPrivateKey,
        localHostname: "build01.example.com",
        localUsername: "builder",
    },
    authenticationMethodsOrder: [SSHAuthenticationMethods.None, SSHAuthenticationMethods.Hostbased],
})
```

The strongest signature algorithm supported by the key is selected unless `algorithm` is set.
The request's signature algorithm uses the strict RFC 4250 name codec. Certificate request names
map to their underlying signature algorithm before signing and verification, and method
construction copies caller-owned metadata. The client also snapshots and freezes the configured
host-based identity during construction; changing the original options object later cannot alter
the hostname, local username, key, or algorithm used by a future connection.
Protect a client host key more strictly than an ordinary user's key: anyone who obtains it may be
able to impersonate users from that host wherever host-based trust is configured.

## Server authentication

Set `banner` to send a login notice once after the user-authentication service starts and before
authentication succeeds.

```ts
import { Server, SSHAuthenticationMethods } from "@bunkerch/modernssh"

const server = new Server({
    hostKeys,
    banner: "Authorized access only. Activity may be monitored.\r\n",
    bannerLanguageTag: "en-US",
    handshakeTimeout: 20_000,
    authenticationTimeout: 10 * 60 * 1000,
    maxAuthenticationAttempts: 20,
})
```

`bannerLanguageTag` is the optional RFC 3066 language tag carried beside the UTF-8 banner. It
defaults to the empty, unspecified tag and requires a non-empty `banner` when set. The server
validates both fields and snapshots them during construction, so malformed local text fails before
listening and later changes to the caller's options object cannot alter the wire message.

`handshakeTimeout` bounds each owned socket from the start of the awaited `preconnect` policy,
through identification, initial key exchange, and acceptance of the `ssh-userauth` service. It
defaults to 20 seconds; `0` disables it. Before identification completes the server cannot safely
send a binary disconnect, so expiry destroys the socket with `Timed out while waiting for SSH
handshake`. A `ServerClient` error listener installed by `preconnect`, or synchronously by the later
`connection` event, observes transport errors; earlier errors without a listener remain contained
and are sent to configured diagnostics. Accepting the service clears this timer before any
authentication policy runs.

When at least one `preconnect` hook is installed, admission is denied until the hook chain completes
without a rejected handler and explicitly sets `allowConnection = true`. A contained async hook
rejection is still reported through Hooker's `uncaughtException` event, but it cannot retain an
allow decision made by an earlier handler. Rejected sockets are terminated before the server emits
`connection` or adds them to `server.clients`. If admission does not settle before
`handshakeTimeout`, transport closure also releases its reserved connection slot.

`authenticationTimeout` bounds the whole authentication phase in milliseconds after the service is
accepted; its RFC-recommended default is ten minutes, and `0` disables this deadline.
`maxAuthenticationAttempts` defaults to 20 and must be a positive integer. Rejected authentication
requests count toward the limit, but the initial `none` discovery request, intermediate password
change or keyboard-interactive messages, and completed factors reported with `partialSuccess` do
not. Reaching either limit sends `SSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE` and closes the
connection.

Policy hooks may perform asynchronous work and are awaited. The timeout remains an absolute
deadline while a hook is pending: a decision completed after expiry is ignored and cannot admit the
client. Choose a shorter application-specific timeout when authentication depends on bounded local
services, and use cancellation inside policy code if abandoning its external work matters.

Every server authentication policy chain must also complete without a rejected handler before the
library honors login, partial-success, signature-challenge, password-change, or interactive-prompt
decisions. Hooker contains and reports the rejection as usual, then authentication fails closed;
an earlier handler's decision cannot survive a later handler failure. This applies equally to
`none`, public-key, host-based, password, keyboard-interactive, and GSS-API authentication.

The keyboard-interactive hook controls every round. Set `prompts` to continue, `allowLogin` to
finish authentication, or neither to reject the method. Empty prompt arrays are valid and require
an empty response message; individual prompt strings must not be empty.

```ts
server.hooker.hook("keyboardInteractiveAuthentication", (_hook, context, decision) => {
    if (context.round === 0) {
        decision.name = "Two-factor login"
        decision.instruction = "Enter your password and current one-time code."
        decision.prompts = [
            { prompt: "Password: ", echo: false },
            { prompt: "One-time code: ", echo: false },
        ]
        return
    }

    decision.allowLogin = verifyResponses(context.username, context.responses ?? [])
})
```

Password hooks receive `newPassword` when the client sends a password-change request. To request a
change, return a prompt instead of accepting or rejecting the original password:

```ts
server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
    if (passwordIsExpired(context.username) && context.newPassword === undefined) {
        decision.requestPasswordChange = { prompt: "Choose a new password: " }
        return
    }
    decision.allowLogin = updateAndVerifyPassword(context)
})
```

For multi-factor authentication, mark a successfully completed factor as partial and explicitly
list the methods that may continue. A final factor sets `allowLogin` instead.

```ts
server.hooker.hook("passwordAuthentication", (_hook, context, decision) => {
    if (!verifyPassword(context.username, context.password)) return
    decision.partialSuccess = true
    decision.authenticationMethods = [SSHAuthenticationMethods.KeyboardInteractive]
})
```

Public-key possession is mandatory for both final and partial success. If policy marks an unsigned
key probe as successful, the server clears that decision and requests a signature; only the
verified signed request can complete the factor.

The server accepts authentication only for the `ssh-connection` target service. An unavailable
service is rejected before any credential policy hook runs. Once a hook reports partial success,
the username and target service are fixed for the rest of that authentication exchange; a peer
that changes either value is disconnected before another factor policy runs. This prevents factors
for different accounts or services from being combined even when a custom client bypasses the
client-side identity guard.

The server advertises only methods with registered policy hooks. Unknown methods are rejected, and
`none` is omitted from every continuation list as required by RFC 4252.

`authenticationSignatureAlgorithms` independently controls the public-key and host-based
signature names a client may use and a server may advertise and accept. The client enforces its
policy even when an older server omits `server-sig-algs`. The server enforces its policy before
invoking an authentication hook, including when a client ignores the advertisement.

The default for both roles contains every implemented modern signature but excludes the SHA-1
`ssh-rsa` forms and the DSS forms. Configure an exact non-empty list to narrow the policy further
or to opt into a legacy peer:

```ts
const client = new Client({
    username: "deploy",
    authenticationSignatureAlgorithms: ["rsa-sha2-512", "rsa-sha2-256"],
})

const server = new Server({
    hostKeys,
    authenticationSignatureAlgorithms: ["rsa-sha2-512", "rsa-sha2-256"],
})
```

Enabling a legacy name is an explicit decision at each endpoint in addition to the server hook's
per-key authorization. Prefer RSA SHA-2 over `ssh-rsa`; do not enable DSS for new deployments. A
pre-authentication `sendAuthenticationExtensions()` update may narrow the advertised list for an
account, but it cannot advertise a signature disabled by the server allowlist.

After success, `ServerClient.username` and `ServerClient.authenticationMethod` expose only the
authenticated principal and the method that completed authentication. Both are `undefined` before
success. The connection does not retain or expose the successful authentication packet: password,
replacement-password, keyboard-interactive response, and signature-bearing request objects remain
scoped to authentication processing. Use `connection.username` for later channel and forwarding
authorization rather than retaining a policy hook's credential context.

The public-key hook receives `context.algorithm` separately from `context.publicKey.data.alg`; for
an RSA SHA-2 request these are, for example, `rsa-sha2-512` and `ssh-rsa`. When a request has no
signature, set `requestSignature` after authorizing the key and algorithm. On the signed retry,
verify `context.signatureMessage` with
`context.publicKey.verifySignature(context.signatureMessage, context.signature)` before setting
`allowLogin`. `requestSignature` is honored only for an unsigned probe. Setting it without
`allowLogin` on an already-signed request denies that request with `SSH_MSG_USERAUTH_FAILURE`; the
server never sends `SSH_MSG_USERAUTH_PK_OK` for a signed request. Hook handlers may be async and are
awaited before the protocol reply is sent.

The `hostbasedAuthentication` hook runs only after the library has cryptographically verified the
RFC 4252 signature. It receives the target username, claimed client hostname and username, host
public key, signature algorithm, observed remote address and port, and signed message. The hook must
still establish that the public key belongs to the claimed host and that this host/user pair may log
in as the target user. Correlate `clientHostname` with `remoteAddress` through trusted forward and
reverse DNS or an equivalent inventory; neither the name nor source address alone proves ownership.

```ts
server.hooker.hook("hostbasedAuthentication", async (_hook, context, decision) => {
    decision.allowLogin = await hostTrustPolicy.authorize({
        targetUser: context.username,
        clientUser: context.clientUsername,
        clientHostname: context.clientHostname,
        remoteAddress: context.remoteAddress,
        hostKey: context.publicKey,
    })
})
```
