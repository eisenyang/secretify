// noinspection ES6UnusedImports
import should from "should";
import Secretify from '../src/secretify.js';

const plainObject = {bankAccount: '1122334455667788', bankPassword: 'password123'};
const plainObjectUnsupported = {bankAccount: 1122334455667788, bankPassword: 'password123'};
const password = '87654321';

describe("Seal & unseal", () => {

    it("Object", () => {
        const secret = Secretify.seal(plainObject, password);
        const decryptObjet = Secretify.unseal(secret, password);
        decryptObjet.should.deepEqual(plainObject);
    });

    it("Object's values array, all string", () => {
        const secret = Secretify.seal(Object.values(plainObject), password);
        const decryptObjet = Secretify.unseal(secret, password, Object.keys(plainObject));
        decryptObjet.should.deepEqual(plainObject);
    });

    it("Object's values array, with one number value, should throw", () => {
        Secretify.seal.bind(null, Object.values(plainObjectUnsupported), password).should.throw();
    });

})

describe("Change password", () => {
    const passwordNew = '12345678';

    it("Should not return undefined", () => {
        const secretify = new Secretify(password);
        const secret = secretify.seal(plainObject);
        secretify.changePassword.bind(null, secret, passwordNew).should.not.undefined();
    });

    it("Result equal", () => {
        const secretify = new Secretify(password);
        const secret = secretify.seal(plainObject);
        const secretNew = secretify.changePassword(secret, passwordNew);
        secretify.unseal(secretNew, passwordNew).should.deepEqual(plainObject);
    });
})
