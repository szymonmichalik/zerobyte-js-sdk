# ZeroByte JavaScript SDK

The JavaScript client for ZeroByte, an end-to-end encrypted relay between two
paired devices of one app. It runs in browsers, Node 20+, Deno, Bun and
Cloudflare Workers. HKDF and SHA-256 come from WebCrypto. ChaCha20-Poly1305,
which WebCrypto does not provide, comes from
[`@noble/ciphers`](https://github.com/paulmillr/noble-ciphers) (MIT, audited),
the only dependency. Type definitions are included.

## How it works

Two devices pair once and agree a 32-byte link key and a link id. From these,
each device derives the mailbox name, an access token and one encryption key
per direction. Every message is sealed with ChaCha20-Poly1305 on the device
that sends it. The relay holds the sealed envelope until the other device
collects it, and it never has a key to open it with.

The wire format is specified in
[Relay Protocol v1](https://github.com/szymonmichalik/zerobyte-protocol/blob/master/relay-v1.md).

## Installation

The package is not on npm yet. Install it from GitHub:

```sh
npm install github:szymonmichalik/zerobyte-js-sdk#v1.0.0
```

It installs as `@zerobyte-cloud/sdk`.

## Usage

```js
import { Credentials, Direction, Link, Relay } from "@zerobyte-cloud/sdk";

// Both devices agreed linkKey (32 bytes) and linkID when they paired.
const credentials = await Credentials.derive(linkKey, linkID);
const relay = new Relay({
  appID: "<your app id>",
  credentials,
  base: "https://relay.example.com/v1/", // your relay
});
const link = new Link({
  credentials,
  sends: Direction.C2P,
  relay,
  lastReceived: savedLastReceived,
});

await link.send(new TextEncoder().encode("hello"));

relay.watch(Direction.P2C, async () => {
  for (const { plaintext } of await link.receive()) handle(plaintext);
});
```

- **Pairing** is the app's job: for example a QR code carrying a fresh 32-byte
  key, or an ECDH exchange confirmed by comparing digits on both screens.
- **Directions.** The primary holds the source of truth and sends
  `Direction.P2C`; the companion sends `Direction.C2P`.
- **State.** Sequence numbers are `BigInt`s (UInt64 on the wire). Persist
  `link.lastReceived` and pass it back next time, so messages are not delivered
  twice.
- **Unpairing.** Call `await link.erase()` to delete the mailbox at once.
- **The relay.** `base` is your relay's `/v1/` URL, with the trailing slash.
  There is no default.
- **Outside the browser.** `Relay` accepts a `fetch` implementation, and
  `watch` accepts a WebSocket class as its third argument.

### In the browser

The access token travels in the `Authorization` header. A browser cannot set
headers on a WebSocket, so `watch` sends it as the subprotocol
`zerobyte.bearer.<token>`; the relay accepts it and never echoes it back.

Keep the link key out of `localStorage` where you can: a non-extractable key in
IndexedDB, or a key the user unlocks.

The app id identifies your app on your relay. Generate one with
`npm run app-id` in a clone of
[zerobyte-relay](https://github.com/szymonmichalik/zerobyte-relay) and add it
to `RELAY_APPS`.

## Testing

```sh
npm install
npm test
```

This runs the protocol vectors and the `Link` tests. To also test against a
real relay, start one locally (see zerobyte-relay) and run:

```sh
RELAY_BASE=http://127.0.0.1:8080/v1/ RELAY_APP=<app id> npm test
```

`test/relay-v1.json` is copied from the independent reference in
[zerobyte-protocol](https://github.com/szymonmichalik/zerobyte-protocol/tree/master/spec).
Never regenerate it from this package.

## Licence

Apache-2.0, see [`LICENSE`](LICENSE).

## About ZeroByte

ZeroByte is an open-source project by Szymon Michalik: the protocol, the relay
and the SDKs. relay.zerobyte.cloud runs the same code for Derived and isn't
open to other apps. To use ZeroByte in your app, run your own relay: see
[zerobyte-relay](https://github.com/szymonmichalik/zerobyte-relay).
