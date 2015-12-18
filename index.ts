import {EncryptResult,DecryptResult,VaultResponse} from "./vault";
var Base64 = require('js-base64').Base64;
var Q = require('q');

export class Vault{
	private _vault:any;
	constructor(vault_token:string=process.env['VAULT_TOKEN'],vault_addr:string=process.env['VAULT_ADDR']||'http://127.0.0.1:8200'){
		this._vault = require("node-vault")({endpoint:vault_addr,token:vault_token});
	}
	createKey(keyName:string):Q.Promise<any>{
		var deferred = Q.defer();
		this._vault.write('transit/keys/'+keyName,{value:true},(err:Error,result:VaultResponse)=>{
			if (err) deferred.reject(err);
			else {
				deferred.resolve(result);
			}
		});
		return deferred.promise;
	}
	encrypt(keyName:string, plaintext:string):Q.Promise<string>{
		var deferred = Q.defer();
		this._vault.write(
				'transit/encrypt/'+keyName,
				{plaintext: Base64.encode(plaintext)},
				(err:Error,result:EncryptResult)=>{
					if (err) deferred.reject(err);
					else {
						deferred.resolve(result.data.ciphertext);
					}
				}
		);
		return deferred.promise;
	}
	decrypt(keyName:string, ciphertext:string):Q.Promise<string>{
		var deferred = Q.defer();
		this._vault.write(
				'transit/decrypt/'+keyName,
				{ciphertext:ciphertext},
				(err:Error,result:DecryptResult)=>{
					if (err) deferred.reject(err);
					else {
						deferred.resolve(Base64.decode(result.data.plaintext));
					}
				}
		);
		return deferred.promise;
	}
	
}
//
//var vault = new Vault();
//
//vault.createKey('bar').then((resp:VaultResponse)=>{
//	console.log("Response:", resp);
//}).catch((err:Error)=>{
//	throw err;
//});

//var text = 'the quick brown fox';
//console.log("Starting text:", text);
//vault.encrypt('foo',text).
//then((ciphertext:string)=>{
//	console.log("Cipher Text:",ciphertext);
//	return ciphertext;
//}).
//then((ciphertext)=>{
//	return vault.decrypt('foo',ciphertext);
//}).
//then((decrypted:string)=>{
//	console.log("Decrypted string:",decrypted);
//	return decrypted;
//}).
//catch(err=>{
//	console.error(err);
//});
