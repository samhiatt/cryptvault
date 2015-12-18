
var assert = require('assert');
var Vault = require('../').Vault;

var vault = new Vault();

describe('Vault', ()=> {
	describe('createKey(key)',()=>{
		it('should create a new encryption key',done=>{
			vault.createKey('bar').then(done).catch((err:Error)=>{
				throw err;
			});
		});
	});
	describe('encrypt(key,val) and decrypt(key,cipher)',()=>{
		it('should encrypt and decrypt the string ', (done)=>{
			var text = 'the quick brown fox';

			vault.encrypt('foo',text).
			then((ciphertext:string)=>{
				console.log("Cipher Text:",ciphertext);
				return ciphertext;
			}).
			then((ciphertext:string)=>{
				return vault.decrypt('foo',ciphertext);
			}).
			then((decrypted:string)=>{
				console.log("Decrypted string:",decrypted);
				assert.equal(decrypted, text);
				done();
			}).
			catch((err:Error)=>{
				throw err;
			});

		});
	});
});