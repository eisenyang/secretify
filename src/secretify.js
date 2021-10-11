const Aes = require("./aes");

module.exports = class Secretify {
    static ALGORITHM = "aes256";
    static IV_LEN = 16;
    static PASSWORD_LEN = 32;
    _password;

    constructor(password = "") {
        this._password = Secretify.normalizePassword(password);
    }

    static normalizePassword(password) {
        if (typeof password !== "string") throw new Error("Password must be a string.");
        const len = password.length;
        return len < this.PASSWORD_LEN
            ? password + ("0".repeat(this.PASSWORD_LEN - len))
            : password.substr(0, this.PASSWORD_LEN);
    }

    static seal(plainObject, password) {
        password = Secretify.normalizePassword(password);
        if (!password) return undefined;

        const aes = new Aes(this.ALGORITHM, password);
        let plain = '';
        if (plainObject instanceof Array) {
            if (plainObject.every(s => typeof s === "string")) {
                plain = plainObject.toString();
            } else {
                throw new Error("Seal string array only");
            }
        } else if (typeof plainObject === "object") {
            plain = JSON.stringify(plainObject);
        } else if (typeof plainObject === "string") {
            plain = plainObject;
        }
        return aes.iv + aes.encrypt(plain);
    }

    static unseal(secret, password, keysArray = null) {
        password = Secretify.normalizePassword(password);
        if (!password) return undefined;
        const retString = this._unseal(secret, password);
        if (keysArray instanceof Array) {
            const strings = retString.split(',');
            if (strings.length === keysArray.length) {
                const retObject = {};
                let i = 0;
                for (const key of keysArray) {
                    retObject[key] = strings[i++]
                }
                return retObject;
            }
        } else {
            const plain = this._unseal(secret, password);
            try {
                return JSON.parse(plain);
            } catch (e) {
                return plain;
            }
        }
    }

    static changePassword(secret, oldPassword, newPassword) {
        try {
            oldPassword = Secretify.normalizePassword(oldPassword);
            newPassword = Secretify.normalizePassword(newPassword);
            const plain = this.unseal(secret, oldPassword);
            return Secretify.seal(plain, newPassword);
        } catch (e) {
            return undefined;
        }
    }

    static _unseal(secret, password) {
        const aes = new Aes(this.ALGORITHM, Secretify.normalizePassword(password), secret.substr(0, this.IV_LEN));
        return aes.decrypt(secret.substring(this.IV_LEN));
    }

    seal(plainObject) {
        return Secretify.seal(plainObject, this._password);
    }

    unseal(secret, keysArray = null) {
        return Secretify.unseal(secret, this._password, keysArray);
    }

    changePassword(secret, newPassword) {
        const newSecret = Secretify.changePassword(secret, this._password, newPassword);
        if (newSecret) {
            this._password = newPassword;
            return newSecret;
        }
        return undefined;
    }
}


