export declare const VERSION: 1;
export declare const HEADER_LENGTH: 10;
export declare const NONCE_LENGTH: 12;
export declare const TAG_LENGTH: 16;
export declare const OVERHEAD: 38;
export declare const MAX_PLAINTEXT_BYTES: number;
export declare const MAX_ENVELOPE_BYTES: number;
export declare const FETCH_LIMIT: 16;

export type DirectionValue = 1 | 2;
export declare const Direction: { readonly P2C: 1; readonly C2P: 2 };

export type EnvelopeErrorCode =
  | "invalid_key"
  | "malformed"
  | "unsupported_version"
  | "wrong_direction"
  | "replayed"
  | "authentication_failed"
  | "too_large";

export declare class ZeroByteError extends Error {
  readonly code: EnvelopeErrorCode;
}

export type RelayErrorCode =
  | "unauthorized"
  | "sequence_conflict"
  | "quota_exceeded"
  | "unavailable"
  | "malformed_response";

export declare class RelayError extends Error {
  readonly code: RelayErrorCode;
  readonly status: number;
  /** For `sequence_conflict`: the relay's last sequence. */
  readonly last: bigint | null;
}

export declare function hex(bytes: Uint8Array): string;
export declare function fromHex(text: string): Uint8Array;
export declare function uuidBytes(uuid: string): Uint8Array;

export declare class Credentials {
  readonly mailboxID: Uint8Array;
  readonly accessToken: Uint8Array;
  readonly mailboxName: string;
  readonly bearerToken: string;
  readonly tokenDigest: string;
  /**
   * @param linkKey 32 bytes agreed at pairing.
   * @param linkID 16 bytes naming the link, or a UUID string.
   */
  static derive(linkKey: Uint8Array, linkID: Uint8Array | string): Promise<Credentials>;
}

export declare function readHeader(envelope: Uint8Array): {
  direction: DirectionValue;
  sequence: bigint;
};

export declare function seal(
  plaintext: Uint8Array,
  options: { direction: DirectionValue; sequence: bigint | number; credentials: Credentials },
): Uint8Array;

export declare function open(
  envelope: Uint8Array,
  options: {
    direction: DirectionValue;
    after?: bigint | number | null;
    credentials: Credentials;
  },
): { sequence: bigint; plaintext: Uint8Array };

export declare function joinWire(envelopes: Uint8Array[]): Uint8Array;
export declare function splitWire(body: Uint8Array): Uint8Array[];

export interface RelayTransport {
  claim(): Promise<void>;
  put(envelope: Uint8Array, direction: DirectionValue, sequence: bigint): Promise<void>;
  fetch(
    direction: DirectionValue,
    after: bigint | null,
  ): Promise<{ envelopes: Uint8Array[]; more: boolean }>;
  lastSequence(direction: DirectionValue): Promise<bigint | null>;
  prune(direction: DirectionValue, through: bigint): Promise<void>;
  erase(): Promise<void>;
}

export declare class Relay implements RelayTransport {
  readonly mailbox: string;
  constructor(options: {
    appID: string;
    credentials: Credentials;
    /** Your relay's `/v1/` URL, with the trailing slash. */
    base: string;
    fetch?: typeof fetch;
  });
  claim(): Promise<void>;
  put(envelope: Uint8Array, direction: DirectionValue, sequence: bigint | number): Promise<void>;
  fetch(
    direction: DirectionValue,
    after?: bigint | number | null,
  ): Promise<{ envelopes: Uint8Array[]; more: boolean }>;
  lastSequence(direction: DirectionValue): Promise<bigint | null>;
  prune(direction: DirectionValue, through: bigint | number): Promise<void>;
  erase(): Promise<void>;
  watch(
    direction: DirectionValue,
    onSequence: (sequence: bigint) => void,
    WebSocketImpl?: typeof WebSocket,
  ): WebSocket;
}

export declare class Link {
  readonly sends: DirectionValue;
  readonly receives: DirectionValue;
  /** Persist between sessions. */
  lastReceived: bigint | null;
  constructor(options: {
    credentials: Credentials;
    sends: DirectionValue;
    relay: RelayTransport;
    lastReceived?: bigint | number | null;
  });
  send(plaintext: Uint8Array): Promise<bigint>;
  receive(): Promise<{ sequence: bigint; plaintext: Uint8Array }[]>;
  erase(): Promise<void>;
}
