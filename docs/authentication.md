# User authentication

`modernssh` implements the RFC 4252 `none`, public-key, host-based, and password methods plus RFC 4256
`keyboard-interactive` authentication. The client uses the configured order, but only attempts
methods that the server advertises. When a factor returns partial success, selection starts a new
stage using the server's new continuation list; this supports multi-factor policies without
hard-coding a particular sequence.

During authentication, `authenticationMethodsRemaining` reflects the latest server continuation
list and `partialAuthenticationSuccess` indicates whether any factor has already succeeded.

## Client authentication

Choose the allowed order with `authenticationMethodsOrder`. `none` is useful as the first entry
because it asks the server which methods may continue. It is never advertised by a server.

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

RFC 4252 banners are delivered independently of the active method:

```ts
client.on("banner", (message, languageTag) => {
    displayLoginNotice(message, languageTag)
})
```

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

RSA identities use RFC 8332 SHA-2 signatures by preference: `rsa-sha2-512`, then
`rsa-sha2-256`. The public key blob remains in the `ssh-rsa` format. When a server supplies the RFC
8308 `server-sig-algs` extension, the client restricts its attempts to the advertised signature
algorithms. `DiskAgent` selects the requested hash locally, while `SSHAgent` sends the corresponding
RFC 9987 RSA SHA-2 flag to the external agent.

ECDSA identities on `nistp256`, `nistp384`, and `nistp521` use the matching RFC 5656 algorithm name
and SHA-2 hash. Disk-backed OpenSSH ECDSA keys and delegated agent signatures use the same public-key
authentication path as Ed25519 and RSA identities.

When a server advertises `publickey-hostbound@openssh.com` version 0, public-key authentication
automatically uses the host-bound request. The signed message then contains the exact host-key blob
that completed key exchange, so a delegated signature cannot be replayed to another server. The
client accepts only the exact version-0 advertisement and otherwise uses RFC 4252 public-key
authentication.

Servers with a `publicKeyAuthentication` hook advertise host-bound authentication automatically.
The same awaited hook handles both forms: `context.hostbound` identifies the bound form and
`context.serverHostKey` is its parsed host key. The implementation rejects a request whose embedded
key differs from the key used for this connection before invoking policy. Applications must still
verify `context.signature` over `context.signatureMessage` before setting `allowLogin`.

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
    authenticationTimeout: 10 * 60 * 1000,
    maxAuthenticationAttempts: 20,
})
```

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
