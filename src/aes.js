const crypto = require("crypto");

module.exports = class Aes {
    _iv;
    _algorithm;
    _securityKey;

    constructor(algorithm, securityKey, iv = null) {
        this._algorithm = algorithm;
        this._securityKey = securityKey;
        this._iv = iv ?? Aes.makeIv();
    }

    get iv() {
        return this._iv;
    }

    static makeIv(size = 16) {
        return crypto.randomBytes(size).toString("base64").substr(0, size)
    }

    encrypt(plainText) {
        let cipherText;
        try {
            const cipher = crypto.createCipheriv(this._algorithm, this._securityKey, this._iv);
            cipherText = cipher.update(plainText, 'utf8', 'base64');
            cipherText += cipher.final('base64');
        } catch (e) {
            console.log(e);
            return null;
        }
        return cipherText;
    }

    decrypt(cipherText) {
        let plainText;
        try {
            let cipher = crypto.createDecipheriv(this._algorithm, this._securityKey, this._iv);
            plainText = cipher.update(cipherText, 'base64', "utf8");
            plainText += cipher.final("utf8");
        } catch (e) {
            console.log(e);
            return null;
        }
        return plainText;
    }
}
