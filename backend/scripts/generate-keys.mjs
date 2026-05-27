import crypto from "node:crypto";

const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519");
const publicKeyDer = publicKey.export({ format: "der", type: "spki" });
const publicKeyHex = publicKeyDer.subarray(publicKeyDer.length - 32).toString("hex");

console.log(
  JSON.stringify(
    {
      sharedHmacHex: crypto.randomBytes(32).toString("hex"),
      ed25519PublicKeyHex: publicKeyHex,
      ed25519PrivateKeyPem: privateKey.export({ format: "pem", type: "pkcs8" }),
      suggestedTokenSecret: crypto.randomBytes(32).toString("hex"),
    },
    null,
    2,
  ),
);
