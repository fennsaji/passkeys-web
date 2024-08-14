"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const tweetnacl_1 = __importDefault(require("tweetnacl"));
const tweetnacl_util_1 = __importDefault(require("tweetnacl-util"));
class PasskeyEd25519X25519Manager {
    constructor() {
        if (typeof tweetnacl_1.default === 'undefined') {
            throw new Error('TweetNaCl.js is not loaded');
        }
    }
    register(username) {
        return __awaiter(this, void 0, void 0, function* () {
            const challenge = tweetnacl_1.default.randomBytes(32);
            const publicKeyCredentialCreationOptions = {
                challenge,
                rp: {
                    name: "Example App",
                    id: window.location.hostname
                },
                user: {
                    id: new TextEncoder().encode(username),
                    name: username,
                    displayName: username
                },
                pubKeyCredParams: [{ alg: -8, type: "public-key" }], // -8 represents EdDSA
                authenticatorSelection: {
                    authenticatorAttachment: "platform",
                    userVerification: "required"
                },
                timeout: 60000
            };
            const credential = yield navigator.credentials.create({
                publicKey: publicKeyCredentialCreationOptions
            });
            console.log("Credential created:", credential);
            return credential;
        });
    }
    authenticate(username) {
        return __awaiter(this, void 0, void 0, function* () {
            const challenge = tweetnacl_1.default.randomBytes(32);
            const publicKeyCredentialRequestOptions = {
                challenge,
                rpId: window.location.hostname,
                userVerification: "required",
                timeout: 60000
            };
            const assertion = yield navigator.credentials.get({
                publicKey: publicKeyCredentialRequestOptions
            });
            console.log("Authentication successful:", assertion);
            return assertion;
        });
    }
    generateEd25519KeyPair() {
        return tweetnacl_1.default.sign.keyPair();
    }
    generateX25519KeyPair() {
        return tweetnacl_1.default.box.keyPair();
    }
    signData(data, privateKey) {
        return tweetnacl_1.default.sign.detached(tweetnacl_util_1.default.decodeUTF8(data), privateKey);
    }
    verifySignature(data, signature, publicKey) {
        return tweetnacl_1.default.sign.detached.verify(tweetnacl_util_1.default.decodeUTF8(data), signature, publicKey);
    }
    encryptData(data, recipientPublicKey) {
        const ephemeralKeyPair = this.generateX25519KeyPair();
        const nonce = tweetnacl_1.default.randomBytes(tweetnacl_1.default.box.nonceLength);
        const messageUint8 = tweetnacl_util_1.default.decodeUTF8(data);
        const encrypted = tweetnacl_1.default.box(messageUint8, nonce, recipientPublicKey, ephemeralKeyPair.secretKey);
        const fullMessage = new Uint8Array(nonce.length + ephemeralKeyPair.publicKey.length + encrypted.length);
        fullMessage.set(nonce);
        fullMessage.set(ephemeralKeyPair.publicKey, nonce.length);
        fullMessage.set(encrypted, nonce.length + ephemeralKeyPair.publicKey.length);
        return fullMessage;
    }
    decryptData(encryptedData, privateKey) {
        const nonce = encryptedData.slice(0, tweetnacl_1.default.box.nonceLength);
        const ephemeralPublicKey = encryptedData.slice(tweetnacl_1.default.box.nonceLength, tweetnacl_1.default.box.nonceLength + tweetnacl_1.default.box.publicKeyLength);
        const ciphertext = encryptedData.slice(tweetnacl_1.default.box.nonceLength + tweetnacl_1.default.box.publicKeyLength);
        const decrypted = tweetnacl_1.default.box.open(ciphertext, nonce, ephemeralPublicKey, privateKey);
        if (!decrypted) {
            throw new Error('Could not decrypt message');
        }
        return tweetnacl_util_1.default.encodeUTF8(decrypted);
    }
}
// Usage
function demo() {
    return __awaiter(this, void 0, void 0, function* () {
        const manager = new PasskeyEd25519X25519Manager();
        const username = "user@example.com";
        try {
            // Register a new passkey
            const credential = yield manager.register(username);
            // Authenticate with the passkey
            const assertion = yield manager.authenticate(username);
            // Generate Ed25519 key pair for signing
            const signingKeyPair = manager.generateEd25519KeyPair();
            // Generate X25519 key pair for encryption
            const encryptionKeyPair = manager.generateX25519KeyPair();
            // Sign data
            const dataToSign = "Message to be signed";
            const signature = manager.signData(dataToSign, signingKeyPair.secretKey);
            console.log("Signature:", tweetnacl_util_1.default.encodeBase64(signature));
            // Verify signature
            const isValid = manager.verifySignature(dataToSign, signature, signingKeyPair.publicKey);
            console.log("Signature valid:", isValid);
            // Encrypt data
            const dataToEncrypt = "Sensitive data protected by X25519 encryption";
            const encryptedData = manager.encryptData(dataToEncrypt, encryptionKeyPair.publicKey);
            console.log("Encrypted:", tweetnacl_util_1.default.encodeBase64(encryptedData));
            // Decrypt data
            const decryptedData = manager.decryptData(encryptedData, encryptionKeyPair.secretKey);
            console.log("Decrypted:", decryptedData);
        }
        catch (error) {
            console.error("Error:", error);
        }
    });
}
demo();
