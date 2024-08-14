import nacl from 'tweetnacl';
import util from 'tweetnacl-util';

class PasskeyEd25519X25519Manager {
    constructor() {
        if (typeof nacl === 'undefined') {
            throw new Error('TweetNaCl.js is not loaded');
        }
    }

    async register(username: string): Promise<PublicKeyCredential> {
        const challenge = nacl.randomBytes(32);

        const publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions = {
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

        const credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
        }) as PublicKeyCredential;

        console.log("Credential created:", credential);
        return credential;
    }

    async authenticate(username: string): Promise<PublicKeyCredential> {
        const challenge = nacl.randomBytes(32);

        const publicKeyCredentialRequestOptions: PublicKeyCredentialRequestOptions = {
            challenge,
            rpId: window.location.hostname,
            userVerification: "required",
            timeout: 60000
        };

        const assertion = await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions
        }) as PublicKeyCredential;

        console.log("Authentication successful:", assertion);
        return assertion;
    }

    generateEd25519KeyPair(): nacl.SignKeyPair {
        return nacl.sign.keyPair();
    }

    generateX25519KeyPair(): nacl.BoxKeyPair {
        return nacl.box.keyPair();
    }

    signData(data: string, privateKey: Uint8Array): Uint8Array {
        return nacl.sign.detached(util.decodeUTF8(data), privateKey);
    }

    verifySignature(data: string, signature: Uint8Array, publicKey: Uint8Array): boolean {
        return nacl.sign.detached.verify(util.decodeUTF8(data), signature, publicKey);
    }

    encryptData(data: string, recipientPublicKey: Uint8Array): Uint8Array {
        const ephemeralKeyPair = this.generateX25519KeyPair();
        const nonce = nacl.randomBytes(nacl.box.nonceLength);
        const messageUint8 = util.decodeUTF8(data);
        const encrypted = nacl.box(messageUint8, nonce, recipientPublicKey, ephemeralKeyPair.secretKey);

        const fullMessage = new Uint8Array(nonce.length + ephemeralKeyPair.publicKey.length + encrypted.length);
        fullMessage.set(nonce);
        fullMessage.set(ephemeralKeyPair.publicKey, nonce.length);
        fullMessage.set(encrypted, nonce.length + ephemeralKeyPair.publicKey.length);

        return fullMessage;
    }

    decryptData(encryptedData: Uint8Array, privateKey: Uint8Array): string {
        const nonce = encryptedData.slice(0, nacl.box.nonceLength);
        const ephemeralPublicKey = encryptedData.slice(
            nacl.box.nonceLength,
            nacl.box.nonceLength + nacl.box.publicKeyLength
        );
        const ciphertext = encryptedData.slice(nacl.box.nonceLength + nacl.box.publicKeyLength);

        const decrypted = nacl.box.open(ciphertext, nonce, ephemeralPublicKey, privateKey);

        if (!decrypted) {
            throw new Error('Could not decrypt message');
        }

        return util.encodeUTF8(decrypted);
    }
}

// Usage
async function demo() {
    const manager = new PasskeyEd25519X25519Manager();
    const username = "user@example.com";

    try {
        // Register a new passkey
        const credential = await manager.register(username);

        // Authenticate with the passkey
        const assertion = await manager.authenticate(username);

        // Generate Ed25519 key pair for signing
        const signingKeyPair = manager.generateEd25519KeyPair();

        // Generate X25519 key pair for encryption
        const encryptionKeyPair = manager.generateX25519KeyPair();

        // Sign data
        const dataToSign = "Message to be signed";
        const signature = manager.signData(dataToSign, signingKeyPair.secretKey);
        console.log("Signature:", util.encodeBase64(signature));

        // Verify signature
        const isValid = manager.verifySignature(dataToSign, signature, signingKeyPair.publicKey);
        console.log("Signature valid:", isValid);

        // Encrypt data
        const dataToEncrypt = "Sensitive data protected by X25519 encryption";
        const encryptedData = manager.encryptData(dataToEncrypt, encryptionKeyPair.publicKey);
        console.log("Encrypted:", util.encodeBase64(encryptedData));

        // Decrypt data
        const decryptedData = manager.decryptData(encryptedData, encryptionKeyPair.secretKey);
        console.log("Decrypted:", decryptedData);
    } catch (error) {
        console.error("Error:", error);
    }
}

demo();