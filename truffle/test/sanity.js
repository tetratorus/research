var bitcore = require('bitcore-lib');
var ECIES = require('bitcore-ecies')();
var Schnorr = artifacts.require('Schnorr');
var Go = require('gonode').Go;
// var contract = artifacts.require('ContractName');

contract('Sanity Tests', function(accounts) {
  it('should encrypt and decrypt data', function() {
    
    var alicePrivateKey = new bitcore.PrivateKey('10274ACD1126740A07688CE5C8FEB13EC298413781B2B8565948A82F7A1E42D4');
    var bobPrivateKey = new bitcore.PrivateKey('55AF2C88EAC3F5B97DBD916C0477C86DE36C6B3C34AA1662840B24ECD93FD42A');
    debugger;
    var data = new Buffer.from('The is a raw data example');
    
    // Encrypt data
    var cypher1 = ECIES.privateKey(alicePrivateKey).publicKey(bobPrivateKey.publicKey);
    var encrypted = cypher1.encrypt(data);
    
    // Decrypt data
    var cypher2 = ECIES.privateKey(bobPrivateKey).publicKey(alicePrivateKey.publicKey);
    var decrypted = cypher2.decrypt(encrypted);
    
    assert.equal(data.toString(), decrypted.toString());
  });

  it('should convert integer to string', async function() {
    await Schnorr.deployed().then(async function(instance) {
      await instance.uintToString(25).then(function(res) {
        return assert.equal('25', res);
      }).catch(function(e) {
        throw e;
      })
      return true
    });
  });

  it('should run go code', async function() {
    var res = await new Promise(function(resolve, reject) {
      var go = new Go({
        path: '../go/bn256.go',
        initAtOnce: true
      }, function(err, res) {
        go.execute({command: 'Hello there...'}, function(result, response) {
          if (result.ok) {
            resolve(response);
          } else if (result.timeout) {
            reject('Command timed out');
          }
          reject('result not ok');
          go.close();
        });
      });
    });
    assert.equal(res.response, 'General Kenobi.')
  });

  it('should sign and verify bn256 Schnorr signature', async function() {
    // generate private key
    var res = await new Promise((resolve, reject) => {
      var go = new Go({
        path: '../go/bn256.go',
        initAtOnce: true
      }, (err, res) => {
        go.execute({command: 'generatePrivateKey'}, (result, response) => {
          if (result.ok) {
            resolve(response);
          } else if (result.timeout) {
            reject('Command timed out');
          }
          reject('result not ok');
          go.close();
        });
      });
    });

    assert.equal(res.response, 'Successfully generated a random point');
    var xGX = res.data.xG.split(",")[0].split("(")[1];
    var xGY = res.data.xG.split(",")[1].split(")")[0].trim();
    assert.equal(res.data.xGX, xGX);
    assert.equal(res.data.xGY, xGY);
    var privateKey = res.data;

    // sign a message
    var message = "Here is a message"

    res = await new Promise((resolve, reject) => {
      var go = new Go({
        path: '../go/bn256.go',
        initAtOnce: true
      }, (err, res) => {
        go.execute({command: 'signMessage', data: {message}}, (result, response) => {
          if (result.ok) {
            resolve(response);
          } else if (result.timeout) {
            reject('Command timed out');
          }
          reject('result not ok');
          go.close();
        });
      });
    });

    assert.equal(res.response, 'Signing message function working')


  });
});
