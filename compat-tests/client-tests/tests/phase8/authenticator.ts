import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import type { AuthenticationResponseJSON, RegistrationResponseJSON } from "@simplewebauthn/server";

export type RegistrationOptions = {
  challenge: string;
  rp: { id: string };
  user: { id: string };
  authenticatorSelection: { userVerification: string };
};
export type AuthenticationOptions = {
  challenge: string;
  rpId: string;
  allowCredentials?: { id: string }[];
};

const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
const jwk = publicKey.export({ format: "jwk" });
const publicKeyCBOR = isoCBOR.encode(new Map<number, number | Uint8Array>([
  [1, 2], [3, -7], [-1, 1],
  [-2, Buffer.from(jwk.x!, "base64url")],
  [-3, Buffer.from(jwk.y!, "base64url")],
]));

const hash = (value: Uint8Array | string) => createHash("sha256").update(value).digest();

/** Signs WebAuthn assertions without substituting the server's verifier. */
export function authenticator(credentialID: string) {
  const id = Buffer.from(credentialID).toString("base64url");
  function authData(rpID: string, flags: number, counter: number) {
    const result = Buffer.alloc(37);
    hash(rpID).copy(result);
    result[32] = flags;
    result.writeUInt32BE(counter, 33);
    return result;
  }
  function clientData(type: string, challenge: string, origin: string) {
    return Buffer.from(JSON.stringify({ type, challenge, origin, crossOrigin: false }));
  }
  return {
    id,
    register(options: RegistrationOptions, origin: string, verified: boolean): RegistrationResponseJSON {
      const credential = Buffer.from(credentialID);
      const length = Buffer.alloc(2);
      length.writeUInt16BE(credential.length);
      const data = Buffer.concat([
        authData(options.rp.id, 0x41 | (verified ? 0x04 : 0), 0),
        Buffer.alloc(16), length, credential, publicKeyCBOR,
      ]);
      return {
        id, rawId: id, type: "public-key", clientExtensionResults: {},
        response: {
          clientDataJSON: clientData("webauthn.create", options.challenge, origin).toString("base64url"),
          attestationObject: Buffer.from(isoCBOR.encode(new Map<string, string | Uint8Array | Map<string, never>>([
            ["fmt", "none"], ["attStmt", new Map()], ["authData", data],
          ]))).toString("base64url"),
          transports: ["internal"],
        },
      };
    },
    authenticate(options: AuthenticationOptions, origin: string, counter: number, flags: number, userHandle: string): AuthenticationResponseJSON {
      const data = authData(options.rpId, flags, counter);
      const client = clientData("webauthn.get", options.challenge, origin);
      return {
        id, rawId: id, type: "public-key", clientExtensionResults: {},
        response: {
          authenticatorData: data.toString("base64url"),
          clientDataJSON: client.toString("base64url"),
          signature: sign("sha256", Buffer.concat([data, hash(client)]), privateKey).toString("base64url"),
          userHandle,
        },
      };
    },
  };
}
