import { generateKeyPairSync } from "node:crypto";

export type WireGuardKeyPair = {
  publicKey: string;
  privateKey: string;
};

function exportRawKey(material: Buffer): Buffer {
  return material.subarray(material.length - 32);
}

export function createWireGuardKeyPair(): WireGuardKeyPair {
  const pair = generateKeyPairSync("x25519", {
    publicKeyEncoding: { format: "der", type: "spki" },
    privateKeyEncoding: { format: "der", type: "pkcs8" },
  }) as unknown as { publicKey: Buffer; privateKey: Buffer };

  return {
    publicKey: exportRawKey(Buffer.from(pair.publicKey)).toString("base64"),
    privateKey: exportRawKey(Buffer.from(pair.privateKey)).toString("base64"),
  };
}
