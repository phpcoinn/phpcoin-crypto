const phpcoinCrypto = require("./index")

phpcoinCrypto.network = 'mainnet'
let account = phpcoinCrypto.generateAccount()
console.log(account)

let msg = "some message";
let signature = phpcoinCrypto.sign(msg, account.privateKey)

console.log(signature)
let res = phpcoinCrypto.verify(msg, signature, account.publicKey)
console.log(res)

let string = "SOME STRING"
let pass = "SOME PASS"
let encrypted = phpcoinCrypto.encryptString(string, pass)
console.log(encrypted)

let decrypted = phpcoinCrypto.decryptString(encrypted, pass)
console.log(decrypted)

let account2 = phpcoinCrypto.importPrivateKey(account.privateKey)
console.log(account2)

let publicKey = phpcoinCrypto.getPublicKey(account.privateKey)
console.log(publicKey)
