import crypto from "crypto";

export default class Secretify {
    static ALGORITHM = "aes256";
    static IV_LEN = 16;
    static PASSWORD_LEN = 32;
    #password;

    constructor(password = "") {
        this.#password = Secretify.normalizePassword(password);
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
            plain = plainObject.toString();
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
                    retObject[key] = strings[i++];
                }
                return retObject;
            }
        } else {
            const plain = Secretify._unseal(secret, password);
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
            const secret = Secretify.seal(plain, newPassword);
            return {secret, password: newPassword};
        } catch (e) {
            return undefined;
        }
    }

    static _unseal(secret, password) {
        const aes = new Aes(this.ALGORITHM, Secretify.normalizePassword(password), secret.substr(0, this.IV_LEN));
        return aes.decrypt(secret.substring(this.IV_LEN));
    }

    seal(plainObject) {
        return Secretify.seal(plainObject, this.#password);
    }

    unseal(secret) {
        return Secretify._unseal(secret, this.#password);
    }

    changePassword(secret, newPassword) {
        const result = Secretify.changePassword(secret, this.#password, newPassword);
        if (result) {
            this.#password = result.password;
            return result;
        }
        return undefined;
    }
}


class Aes {
    iv;

    constructor(algorithm, securityKey, iv = null) {
        this.algorithm = algorithm;
        this.securityKey = securityKey;
        this.iv = iv ?? Aes.makeIv();
    }

    static makeIv(size = 16) {
        return crypto.randomBytes(size).toString("base64").substr(0, size)
    }

    encrypt(plainText) {
        let cipherText;
        try {
            const cipher = crypto.createCipheriv(this.algorithm, this.securityKey, this.iv);
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
            let cipher = crypto.createDecipheriv(this.algorithm, this.securityKey, this.iv);
            plainText = cipher.update(cipherText, 'base64', "utf8");
            plainText += cipher.final("utf8");
        } catch (e) {
            console.log(e);
            return null;
        }
        return plainText;
    }
}
