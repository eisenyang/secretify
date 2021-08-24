import Secretify from "secretify";
const plainObject = {
    bankAccount: 1122334455667788,
    bankPassword: '12345678'
};

const password = '87654321';
const secret = Secretify.seal(plainObject, password);
console.log(secret);

const decryptObjet = Secretify.unseal(secret, password, Object.keys(plainObject));
console.log(decryptObjet);


