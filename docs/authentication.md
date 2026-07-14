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
resolved per-connection strategy does not mutate `client.options.authenticationMethodsOrder`.

```ts
import { Client, SSHAuthenticationMethods } from "modernssh"

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
already attempted in this stage and the server's latest continuation list. After partial success,
the attempted set is cleared and the hook runs for the new stage. A replacement must be configured,
must not have failed in the current stage, and must appear in the continuation list when one is
known. Set `decision.method` to `undefined` to stop authentication.

```ts
client.hooker.hook("authenticationMethod", async (_hook, context, decision) => {
    if (context.methodsRemaining?.includes(SSHAuthenticationMethods.KeyboardInteractive)) {
        const available = await secondFactorDevice.isAvailable()
        if (available) decision.method = SSHAuthenticationMethods.KeyboardInteractive
    }
})
```

Method selection does not carry secrets. Configure keys through `privateKey` or `agent`, and supply
interactive passwords and challenge responses through their dedicated awaited hooks.

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
Encrypted input uses `passphrase`; the client parses it during construction and does not retain the
encoded key or passphrase in `client.options`.

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

`agent` may also be the UNIX-domain socket path of an RFC 9987 agent. The client normalizes that
path to an `SSHAgent` during construction; omitting or passing an empty path does not implicitly
enable `$SSH_AUTH_SOCK`.

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
} from "modernssh"

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
algorithms. Direct private keys, `PrivateKeyAgent`, and `DiskAgent` select the requested hash
locally, while `SSHAgent` sends the corresponding RFC 9987 RSA SHA-2 flag to the external agent.
Ordinary and host-bound requests encode these identifiers with the shared RFC 4250 SSH-name codec;
malformed, non-ASCII, overlong, or comma-containing names are rejected before key policy.

ECDSA identities on `nistp256`, `nistp384`, and `nistp521` use the matching RFC 5656 algorithm name
and SHA-2 hash. Disk-backed OpenSSH ECDSA keys and delegated agent signatures use the same public-key
authentication path as Ed25519 and RSA identities.

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
to the awaited hook. Draft-only certificate names are not added to interoperable defaults.

On the server, `context.certificate` contains the verified certificate when present. Before the
awaited policy hook runs, the library checks its CA signature, user role, validity interval, and
the request's possession signature. The hook must still trust the CA explicitly, authorize at
least one principal for `context.username`, reject or implement every critical option, and compose
certificate restrictions with application policy. Extensions grant nothing by themselves.

Host-based authentication proves possession of a client machine's private host key and sends the
claimed client hostname and local username for authorization. Configure all three explicitly and
include `Hostbased` in the method order. The hostname must be a non-empty ASCII DNS name; a trailing
root dot is accepted.

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
construction copies caller-owned metadata.
Protect a client host key more strictly than an ordinary user's key: anyone who obtains it may be
able to impersonate users from that host wherever host-based trust is configured.

## Server authentication

Set `banner` to send a login notice once after the user-authentication service starts and before
authentication succeeds.

```ts
import { Server, SSHAuthenticationMethods } from "modernssh"

const server = new Server({
    hostKeys,
    banner: "Authorized access only. Activity may be monitored.\r\n",
    handshakeTimeout: 20_000,
    authenticationTimeout: 10 * 60 * 1000,
    maxAuthenticationAttempts: 20,
})
```

`handshakeTimeout` bounds each admitted socket after the awaited `preconnect` policy, through
identification, initial key exchange, and acceptance of the `ssh-userauth` service. It defaults to
20 seconds; `0` disables it. Before identification completes the server cannot safely send a binary
disconnect, so expiry destroys the socket and emits `Timed out while waiting for SSH handshake`
through that `ServerClient`'s `error` event. Accepting the service clears this timer before any
authentication policy runs.

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

The server advertises only methods with registered policy hooks. Unknown methods are rejected, and
`none` is omitted from every continuation list as required by RFC 4252.

The public-key hook receives `context.algorithm` separately from `context.publicKey.data.alg`; for
an RSA SHA-2 request these are, for example, `rsa-sha2-512` and `ssh-rsa`. When a request has no
signature, set `requestSignature` after authorizing the key and algorithm. On the signed retry,
verify `context.signatureMessage` with
`context.publicKey.verifySignature(context.signatureMessage, context.signature)` before setting
`allowLogin`. Hook handlers may be async and are awaited before the protocol reply is sent.

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
