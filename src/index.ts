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
        const firstSalt = new Uint8Array(new Array(32).fill(1)).buffer;
        const publicKeyCredentialCreationOptions: any = {
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
            pubKeyCredParams: [{ alg: -7, type: "public-key" }], // -8 represents EdDSA
            authenticatorSelection: {
                authenticatorAttachment: "cross-platform",
                userVerification: "required"
            },
            timeout: 60000,
            extensions: {
                prf: {
                    eval: {
                        first: firstSalt,
                    },
                },
            },
        };

        const credential = await navigator.credentials.create({
            publicKey: publicKeyCredentialCreationOptions
        }) as PublicKeyCredential;

        console.log("Credential created:", credential);
        console.log(credential.getClientExtensionResults());
        return credential;
    }

    async authenticate(username: string): Promise<PublicKeyCredential> {
        const challenge = nacl.randomBytes(32);

        const firstSalt = new Uint8Array(new Array(32).fill(1)).buffer;
        const publicKeyCredentialRequestOptions: any = {
            challenge,
            rpId: window.location.hostname,
            userVerification: "required",
            timeout: 60000,
            extensions: {
                prf: {
                    eval: {
                        first: firstSalt,
                    },
                },
            },
        };

        const assertion = await navigator.credentials.get({
            publicKey: publicKeyCredentialRequestOptions
        }) as PublicKeyCredential;
        const auth1ExtensionResults = assertion.getClientExtensionResults();
        console.log(auth1ExtensionResults);
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
        console.log(JSON.stringify(credential));

        // Authenticate with the passkey
        const assertion = await manager.authenticate(username);
        console.log(JSON.stringify(assertion));

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

// demo();

// wholeFlow();

async function register(username: String) { 
    const firstSalt = new Uint8Array(new Array(32).fill(1)).buffer;
    const regCredential: any = await navigator.credentials.create({
        publicKey: {
            challenge: new Uint8Array([1, 2, 3, 4]), // Example value
            rp: {
                name: "SimpleWebAuthn Example",
                id: "localhost",
                icon :"https://sovereignwallet.network/favicon.ico"
            },
            user: {
                id: new Uint8Array([5, 6, 7, 8]),  // Example value
                name: username,
                displayName: username,
            },
            pubKeyCredParams: [
                { alg: -8, type: "public-key" },   // Ed25519
                { alg: -7, type: "public-key" },   // ES256
                { alg: -257, type: "public-key" }, // RS256
            ],
            authenticatorSelection: {
                userVerification: "required",
                authenticatorAttachment: "cross-platform",
                residentKey: "required",
            },
            extensions: {
                prf: {
                    eval: {
                        first: firstSalt,
                    },
                },
            },
        },

    } as any);
    console.log(regCredential?.getClientExtensionResults());
    console.log("Transports: ", regCredential.response.getTransports());
    return {rawId: regCredential.rawId, transports: regCredential.response.getTransports(), firstSalt: firstSalt};
}

async function authenticate(rawId: any, transports: any, firstSalt: any) { 
    const auth1Credential: any = await navigator.credentials.get({
        publicKey: {
            challenge: new Uint8Array([9, 0, 1, 2]), // Example value
            allowCredentials: [
                {
                    id: rawId,  // Example value
                    transports,
                    type: "public-key",
                },
            ],
            rpId: "localhost",
            // This must always be either "discouraged" or "required".
            // Pick one and stick with it.
            userVerification: "required",
            extensions: {
                prf: {
                    eval: {
                        first: firstSalt,
                    },
                },
            },
        },
    } as any);
    const auth1ExtensionResults = auth1Credential?.getClientExtensionResults();
    console.log(auth1ExtensionResults);
    return {key: auth1ExtensionResults.prf.results.first};
}

async function encryptData(key: any, data: any) { 
    const inputKeyMaterial = new Uint8Array(
        key,
    );
    const keyDerivationKey = await crypto.subtle.importKey(
        "raw",
        inputKeyMaterial,
        "HKDF",
        false,
        ["deriveKey"],
    );


    // Never forget what you set this value to or the key can't be
    // derived later
    const label = "encryption key";
    const info = new TextEncoder().encode(label);
    // `salt` is a required argument for `deriveKey()`, but should
    // be empty
    const salt = new Uint8Array();

    const encryptionKey = await crypto.subtle.deriveKey(
        { name: "HKDF", info, salt, hash: "SHA-256" },
        keyDerivationKey,
        { name: "AES-GCM", length: 256 },
        // No need for exportability because we can deterministically
        // recreate this key
        false,
        ["encrypt", "decrypt"],
    );

    // Keep track of this `nonce`, you'll need it to decrypt later!
    // FYI it's not a secret so you don't have to protect it.
    const nonce = crypto.getRandomValues(new Uint8Array(12));

    const encrypted = await crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        encryptionKey,
        new TextEncoder().encode(data),
    );
    return {encrypted: encrypted, nonce: nonce};
}

async function decryptData(key: any, encrypted: any, nonce: any) { 

    const inputKeyMaterial = new Uint8Array(
        key,
    );
    const keyDerivationKey = await crypto.subtle.importKey(
        "raw",
        inputKeyMaterial,
        "HKDF",
        false,
        ["deriveKey"],
    );


    // Never forget what you set this value to or the key can't be
    // derived later
    const label = "encryption key";
    const info = new TextEncoder().encode(label);
    // `salt` is a required argument for `deriveKey()`, but should
    // be empty
    const salt = new Uint8Array();

    const encryptionKey = await crypto.subtle.deriveKey(
        { name: "HKDF", info, salt, hash: "SHA-256" },
        keyDerivationKey,
        { name: "AES-GCM", length: 256 },
        // No need for exportability because we can deterministically
        // recreate this key
        false,
        ["encrypt", "decrypt"],
    );
    const decrypted = await crypto.subtle.decrypt(
        // `nonce` should be the same value from Step 2.3
        { name: "AES-GCM", iv: nonce },
        encryptionKey,
        encrypted,
    );
    console.log((new TextDecoder()).decode(decrypted));
    return (new TextDecoder()).decode(decrypted);
}

async function wholeFlow() {
    /**
 * This value is for sake of demonstration. Pick 32 random
 * bytes. `salt` can be static for your site or unique per
 * credential depending on your needs.
 */
    let { rawId, transports, firstSalt } = await register("did:ssid:fenn");

    let { key } = await authenticate(rawId, transports, firstSalt);

    let { encrypted, nonce } = await encryptData(key, "Hello, world!");
    let decrypted = await decryptData(key, encrypted, nonce);
    console.log(decrypted);
    // hello readers 🥳
}

let RawId: any, Transports: any, FirstSalt: any, Key: any, Nonce: any, EncryptedText: any;

async function onRegister(username: String) {
    console.log("Registering");
    let { rawId, transports, firstSalt } = await register(username);
    RawId = rawId;
    Transports = transports;
    FirstSalt = firstSalt;
    console.log(rawId, transports, firstSalt);
}

async function onAuthenticate(username: String) { 
    console.log("Authenticating");
    let rawId: any = RawId;
    let transports: any = Transports;
    let firstSalt: any = FirstSalt;
    console.log(rawId, transports, firstSalt);
    let { key } = await authenticate(rawId, transports, firstSalt);
    Key = key;
}

async function onEncrypt(text: String) {
    console.log("Encrypting");
    let key = Key;
    try {
        let { encrypted, nonce } = await encryptData(key, text);
        console.log(encrypted, nonce);

        Nonce = nonce;
        EncryptedText = encrypted;

        let encryptedBase64 = btoa(String.fromCharCode(...new Uint8Array(encrypted)));
        let nonceBase64 = btoa(String.fromCharCode(...new Uint8Array(nonce)));
        const element = document.getElementById("encrypt_output");
        if (element) {
            element.textContent = `${encryptedBase64}::${nonceBase64}`; // Display encrypted text for copying
        }
    } catch (error) {
        console.error(error);
    }
}

async function onDecrypt(encrypted: string) { 
    let [encryptedBase64, nonceBase64] = encrypted.split("::");
    let nonce = new Uint8Array(atob(nonceBase64).split("").map(c => c.charCodeAt(0)));
    let encrypted_text = new Uint8Array(atob(encryptedBase64).split("").map(c => c.charCodeAt(0)));

    console.log("Decrypting");
    let key = Key;
    try {
        let decrypted = await decryptData(key, encrypted_text, nonce);
        const element = document.getElementById("decrypt_output");
        if (element) {
            element.textContent = JSON.stringify(decrypted);
        }
    } catch (error) {
        console.error(error);
    }
}


// Attach the function to the button click event

document.getElementById('register').addEventListener('click', () => {

    const username = (document.getElementById('username') as HTMLInputElement).value;
    onRegister(username)
});
document.getElementById('authenticate').addEventListener('click', () => {

    const username = (document.getElementById('username') as HTMLInputElement).value;
    onAuthenticate(username)
});
document.getElementById('encrypt').addEventListener('click', () => {
    const text = (document.getElementById('encrypt_text') as HTMLInputElement).value;
    onEncrypt(text);
});
document.getElementById('decrypt').addEventListener('click', () => {
    const text = (document.getElementById('decrypt_text') as HTMLInputElement).value;
    onDecrypt(text);
});
