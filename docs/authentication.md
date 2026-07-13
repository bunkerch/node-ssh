# User authentication

`modernssh` implements the RFC 4252 `none`, public-key, and password methods plus RFC 4256
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

## Server authentication

Set `banner` to send a login notice once after the user-authentication service starts and before
authentication succeeds.

```ts
import { Server, SSHAuthenticationMethods } from "modernssh"

const server = new Server({
    hostKeys,
    banner: "Authorized access only. Activity may be monitored.\r\n",
})
```

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
