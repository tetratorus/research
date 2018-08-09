var bitcore = require('bitcore-lib');
var ECIES = require('bitcore-ecies')();

var alicePrivateKey = new bitcore.PrivateKey('10274ACD1126740A07688CE5C8FEB13EC298413781B2B8565948A82F7A1E42D4');
var bobPrivateKey = new bitcore.PrivateKey('55AF2C88EAC3F5B97DBD916C0477C86DE36C6B3C34AA1662840B24ECD93FD42A');

var data = new Buffer.from('The is a raw data example');

// Encrypt data
var cypher1 = ECIES.privateKey(alicePrivateKey).publicKey(bobPrivateKey.publicKey);
var encrypted = cypher1.encrypt(data);

// Decrypt data
var cypher2 = ECIES.privateKey(bobPrivateKey).publicKey(alicePrivateKey.publicKey);
var decrypted = cypher2.decrypt(encrypted);

console.log(data.toString() == decrypted.toString());