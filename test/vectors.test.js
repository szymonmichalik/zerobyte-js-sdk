// Known answers from the independent reference (zerobyte-protocol, spec/vectors.py),
// copied as relay-v1.json. Never regenerate them from this package.

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { test } from "node:test";

import {
  Credentials,
  Direction,
  Link,
  MAX_PLAINTEXT_BYTES,
  Relay,
  RelayError,
  ZeroByteError,
  fromHex,
  hex,
  joinWire,
  open,
  seal,
  splitWire,
} from "../src/index.js";

const v = JSON.parse(readFileSync(new URL("./relay-v1.json", import.meta.url)));
const creds = (i) =>
  Credentials.derive(fromHex(v.credentials[i].linkKey), fromHex(v.credentials[i].linkId));

test("Credentials match every vector set", async () => {
  for (const [i, set] of v.credentials.entries()) {
    const c = await creds(i);
    assert.equal(c.mailboxName, set.mailbox);
    assert.equal(c.bearerToken, set.bearer);
    assert.equal(c.tokenDigest, set.tokenDigest);
    assert.equal(hex(c.keys[1]), set.p2cKey);
    assert.equal(hex(c.keys[2]), set.c2pKey);
  }
  const fromUUID = await Credentials.derive(
    fromHex(v.credentials[0].linkKey),
    "6F1C2A3B-4D5E-4F60-8172-93A4B5C6D7E8",
  );
  assert.equal(fromUUID.mailboxName, v.credentials[0].mailbox);
});

test("Sealing with the vector nonce gives the vector envelope, and it opens", async () => {
  for (const e of v.envelopes) {
    const c = await creds(e.credentials);
    const sealed = seal(fromHex(e.plaintext), {
      direction: e.direction,
      sequence: BigInt(e.sequence),
      credentials: c,
      nonce: fromHex(e.nonce),
    });
    assert.equal(hex(sealed), e.envelope);
    const opened = open(fromHex(e.envelope), { direction: e.direction, credentials: c });
    assert.equal(opened.sequence, BigInt(e.sequence));
    assert.equal(hex(opened.plaintext), e.plaintext);
  }
});

test("Every rejection vector is refused with its error", async () => {
  for (const r of v.rejections) {
    const c = await creds(r.credentials);
    assert.throws(
      () =>
        open(fromHex(r.envelope), {
          direction: r.direction,
          after: r.after === null ? null : BigInt(r.after),
          credentials: c,
        }),
      (error) => error instanceof ZeroByteError && error.code === r.error,
      r.why,
    );
  }
});

test("Fetch bodies join and split as the vectors say", () => {
  for (const w of v.wire) {
    assert.equal(hex(joinWire(w.envelopes.map(fromHex))), w.body);
    assert.deepEqual(splitWire(fromHex(w.body)).map(hex), w.envelopes);
  }
  for (const w of v.wireRejections) {
    assert.throws(() => splitWire(fromHex(w.body)), RelayError, w.why);
  }
});

test("Wrong key sizes and oversized plaintext are refused", async () => {
  await assert.rejects(Credentials.derive(new Uint8Array(31), new Uint8Array(16)), {
    code: "invalid_key",
  });
  const c = await creds(0);
  assert.throws(
    () => seal(new Uint8Array(MAX_PLAINTEXT_BYTES + 1), { direction: 1, sequence: 1, credentials: c }),
    { code: "too_large" },
  );
});

// A relay in memory with the server's rules.
class MemoryRelay {
  constructor() {
    this.boxes = { 1: [], 2: [] };
    this.last = { 1: null, 2: null };
    this.prunes = [];
  }
  async claim() {}
  async put(envelope, direction, sequence) {
    const s = BigInt(sequence);
    if (this.last[direction] !== null && s <= this.last[direction]) {
      throw new RelayError("sequence_conflict", 409, this.last[direction]);
    }
    this.boxes[direction].push([s, envelope]);
    this.last[direction] = s;
  }
  inject(envelope, direction, sequence) {
    this.boxes[direction].push([BigInt(sequence), envelope]);
    this.boxes[direction].sort((a, b) => (a[0] < b[0] ? -1 : 1));
    this.last[direction] = BigInt(sequence);
  }
  async fetch(direction, after) {
    const waiting = this.boxes[direction].filter(([s]) => s > BigInt(after ?? 0));
    return { envelopes: waiting.slice(0, 16).map(([, e]) => e), more: waiting.length > 16 };
  }
  async lastSequence(direction) {
    return this.last[direction];
  }
  async prune(direction, through) {
    this.prunes.push(through);
    this.boxes[direction] = this.boxes[direction].filter(([s]) => s > through);
  }
  async erase() {
    this.boxes = { 1: [], 2: [] };
  }
}

test("A link delivers in order, once, prunes, and drops forgeries", async () => {
  const c = await creds(1);
  const relay = new MemoryRelay();
  const phone = new Link({ credentials: c, sends: Direction.P2C, relay });
  const laptop = new Link({ credentials: c, sends: Direction.C2P, relay });
  await Promise.all(
    Array.from({ length: 20 }, (_, i) => phone.send(new TextEncoder().encode(`m${i + 1}`))),
  );
  const forged = seal(new Uint8Array([1]), { direction: 1, sequence: 21, credentials: await creds(0) });
  relay.inject(forged, 1, 21);
  const got = await laptop.receive();
  assert.deepEqual(
    got.map((m) => new TextDecoder().decode(m.plaintext)),
    Array.from({ length: 20 }, (_, i) => `m${i + 1}`),
  );
  assert.equal(laptop.lastReceived, 20n);
  assert.deepEqual(relay.prunes, [21n]);
  assert.deepEqual(await laptop.receive(), []);
  assert.deepEqual(relay.prunes, [21n]);

  const restarted = new Link({ credentials: c, sends: Direction.P2C, relay });
  assert.equal(await restarted.send(new Uint8Array([9])), 22n);
});

test("The endpoint is built from the base URL", async () => {
  const c = await creds(0);
  const relay = new Relay({
    appID: "01a1601b-fa85-7d58-b2a2-1416e0a6b054",
    credentials: c,
    base: "https://relay.example.com/v1/",
  });
  assert.equal(
    relay.mailbox,
    `https://relay.example.com/v1/01a1601b-fa85-7d58-b2a2-1416e0a6b054/mailbox/${c.mailboxName}`,
  );
});

test("A relay without a base URL is refused", async () => {
  const c = await creds(0);
  assert.throws(
    () => new Relay({ appID: "01a1601b-fa85-7d58-b2a2-1416e0a6b054", credentials: c }),
    TypeError,
  );
});

// Against a running relay: RELAY_BASE=http://127.0.0.1:8080/v1/ RELAY_APP=<id> npm test
test("End to end against a real relay", { skip: !process.env.RELAY_BASE }, async () => {
  const linkKey = crypto.getRandomValues(new Uint8Array(32));
  const linkID = crypto.getRandomValues(new Uint8Array(16));
  const c = await Credentials.derive(linkKey, linkID);
  const make = (sends) =>
    new Link({
      credentials: c,
      sends,
      relay: new Relay({ appID: process.env.RELAY_APP, credentials: c, base: process.env.RELAY_BASE }),
    });
  const phone = make(Direction.P2C);
  const laptop = make(Direction.C2P);

  const watcher = new Relay({ appID: process.env.RELAY_APP, credentials: c, base: process.env.RELAY_BASE });
  await phone.send(new Uint8Array([0]));
  const heard = new Promise((resolve, reject) => {
    const socket = watcher.watch(Direction.P2C, (s) => {
      socket.close();
      resolve(s);
    });
    socket.addEventListener("error", reject);
    socket.addEventListener("open", () => phone.send(new TextEncoder().encode("hello")));
  });
  assert.equal(await heard, 2n);
  const got = await laptop.receive();
  assert.deepEqual(got.map((m) => new TextDecoder().decode(m.plaintext)), ["\u0000", "hello"]);
  await laptop.send(new TextEncoder().encode("ack"));
  assert.equal(new TextDecoder().decode((await phone.receive())[0].plaintext), "ack");
  await phone.erase();
});
