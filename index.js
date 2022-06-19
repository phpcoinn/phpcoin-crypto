const ellipticcurve = require("starkbank-ecdsa");
const Base58 = require("base-58")
const crypto = require("crypto");
const Ecdsa = ellipticcurve.Ecdsa;
const PrivateKey = ellipticcurve.PrivateKey;
const PublicKey = ellipticcurve.PublicKey;
const Signature = ellipticcurve.Signature;

let networks = {
    mainnet:{
        network_prefix: "38"
    },
    "mainnet-alpha":{
        network_prefix: "38"
    },
    testnet: {
        network_prefix: "30"
    }
}

const defaultNetwork = "mainnet"

let pem2coin = (pem) => {
    let pemB58 = pem.replace('-----BEGIN EC PRIVATE KEY-----','')
    pemB58 = pemB58.replace('-----END EC PRIVATE KEY-----','')
    pemB58 = pemB58.replace('-----BEGIN PUBLIC KEY-----','')
    pemB58 = pemB58.replace('-----END PUBLIC KEY-----','')
    pemB58 = pemB58.replace(/\n/g,'')
    pemB58 = Buffer.from(pemB58, 'base64')
    pemB58 = Base58.encode(pemB58)
    return pemB58
}

let coin2pem = (coin, private_key = false) => {
    let data = Base58.decode(coin)
    data = Buffer.from(data).toString('base64')
    let lines = str_split(data, 64)
    lines = lines.join('\n')
    if(private_key) {
        return '-----BEGIN EC PRIVATE KEY-----\n' + lines + '\n-----END EC PRIVATE KEY-----\n'
    } else {
        return '-----BEGIN EC PUBLIC KEY-----\n' + lines + '\n-----END EC PUBLIC KEY-----\n'
    }
}

let getAddress = (pubkey, network = defaultNetwork) => {
    let network_prefix = networks[network].network_prefix
    let hash1 = crypto.createHash('sha256').update(pubkey).digest('hex');
    let hash2 = crypto.createHash('ripemd160').update(hash1).digest('hex');
    let baseAddress = network_prefix + hash2
    let checksumCalc1 = crypto.createHash('sha256').update(baseAddress).digest('hex')
    let checksumCalc2 = crypto.createHash('sha256').update(checksumCalc1).digest('hex')
    let checksumCalc3 = crypto.createHash('sha256').update(checksumCalc2).digest('hex')
    let checksum = checksumCalc3.substr(0, 8)
    let addreessHex = baseAddress + checksum
    let address = Buffer.from(addreessHex, 'hex')
    let addressB58 = Base58.encode(address)
    return addressB58
}

let verifyAddress = (address, network = defaultNetwork) => {
    let network_prefix = networks[network].network_prefix
    let addressBin = Base58.decode(address)
    let addressHex = Buffer.from(addressBin).toString('hex')
    let addressChecksum = addressHex.substr(addressHex.length - 8, addressHex.length)
    let baseAddress = addressHex.substr(0, addressHex.length-8)
    if(baseAddress.substr(0,2)!==network_prefix) {
        return false
    }
    let checksumCalc1 = crypto.createHash('sha256').update(baseAddress).digest('hex')
    let checksumCalc2 = crypto.createHash('sha256').update(checksumCalc1).digest('hex')
    let checksumCalc3 = crypto.createHash('sha256').update(checksumCalc2).digest('hex')
    let checksum = checksumCalc3.substr(0, 8)
    let valid = addressChecksum === checksum
    return valid
}

function str_split (string, splitLength) { // eslint-disable-line camelcase
    //  discuss at: https://locutus.io/php/str_split/
    // original by: Martijn Wieringa
    // improved by: Brett Zamir (https://brett-zamir.me)
    // bugfixed by: Onno Marsman (https://twitter.com/onnomarsman)
    //  revised by: Theriault (https://github.com/Theriault)
    //  revised by: Rafał Kukawski (https://blog.kukawski.pl)
    //    input by: Bjorn Roesbeke (https://www.bjornroesbeke.be/)
    //   example 1: str_split('Hello Friend', 3)
    //   returns 1: ['Hel', 'lo ', 'Fri', 'end']
    if (splitLength === null) {
        splitLength = 1
    }
    if (string === null || splitLength < 1) {
        return false
    }
    string += ''
    const chunks = []
    let pos = 0
    const len = string.length
    while (pos < len) {
        chunks.push(string.slice(pos, pos += splitLength))
    }
    return chunks
}

function privateKeyToPem(privateKeyBase58) {
    let private_key_bin = Base58.decode(privateKeyBase58)
    let private_key_base64 = Buffer.from(private_key_bin).toString('base64');
    let private_key_pem = '-----BEGIN EC PRIVATE KEY-----\n'
        + str_split(private_key_base64, 64)
            .join('\n')
        + '\n-----END EC PRIVATE KEY-----\n'
    let privateKey = PrivateKey.fromPem(private_key_pem)
    return privateKey
}

module.exports = {
    generateAccount(network = defaultNetwork) {
        let privateKey = new PrivateKey();
        let privateKeyPem = privateKey.toPem()
        let privateKeyB58 = pem2coin(privateKeyPem)
        let publicKey = privateKey.publicKey();
        let publicKeyPem = publicKey.toPem()
        let publicKeyB58 = pem2coin(publicKeyPem)
        let address = getAddress(publicKeyB58, network)
        return {
            privateKey: privateKeyB58,
            publicKey: publicKeyB58,
            address,
            network
        }
    },
    getAddress,
    pem2coin,
    coin2pem,
    sign(data, privateKey) {
        let privateKeyPem = privateKeyToPem(privateKey)
        let signature = Ecdsa.sign(data, privateKeyPem);
        let signature_b64 = signature.toBase64()
        let signature_bin = Buffer.from(signature_b64, 'base64')
        let signature_b58 = Base58.encode(signature_bin)
        return signature_b58
    },
    verify (data, signature, publicKey) {
        let signature_bin = Base58.decode(signature)
        let signature_b64 = Buffer.from(signature_bin).toString('base64')
        let signatureDer = Signature.fromBase64(signature_b64)
        let publicKeyPem = coin2pem(publicKey)
        let publicKeyDer = PublicKey.fromPem(publicKeyPem);
        let res = Ecdsa.verify(data, signatureDer, publicKeyDer)
        return res
    },
    encryptString(str, pass) {
        let passphrase = crypto.createHash('sha256').update(pass).digest().toString('hex').substr(0, 32)
        let iv = crypto.randomBytes(16).toString('hex').substr(0, 16)
        let cipher = crypto.createCipheriv('aes-256-cbc', passphrase, iv)
        let enc = cipher.update(str, 'utf8', 'base64')
        enc += cipher.final('base64')
        let enc2 = iv + enc
        let enc3 = Buffer.from(enc2).toString('base64')
        return enc3
    },
    decryptString(encrypted, pass) {
        let passphrase = crypto.createHash('sha256').update(pass).digest().toString('hex').substr(0, 32)
        let enc2 = Buffer.from(encrypted, 'base64').toString()
        let iv = enc2.substr(0, 16)
        let enc = enc2.substr(16)
        let decipher = crypto.createDecipheriv('aes-256-cbc', passphrase, iv)
        let decrypted = decipher.update(enc, 'base64', 'utf8')
        let str = (decrypted + decipher.final('utf8'))
        return str
    },
    importPrivateKey(privateKey, network = defaultNetwork) {
        try {
            let privateKeyPem = privateKeyToPem(privateKey)
            let publicKeyDer = privateKeyPem.publicKey()
            let publicKeyPem = publicKeyDer.toPem()
            let publicKey = pem2coin(publicKeyPem)
            let address = getAddress(publicKey, network)
            if(!verifyAddress(address, network)) {
                return false
            }
            return {
                privateKey,publicKey,address
            }
        } catch (e) {
            return false
        }
    },
    getPublicKey(private_key) {
        let privateKeyPem = privateKeyToPem(private_key)
        let publicKeyDer = privateKeyPem.publicKey()
        let publicKeyPem = publicKeyDer.toPem()
        let publicKey = pem2coin(publicKeyPem)
        return publicKey
    },
    privateKeyToPem,
    network: defaultNetwork
}


