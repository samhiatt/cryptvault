import Promise = Q.Promise;
var assert = require('assert');
import {VaultStatus} from "../vault";
import {CryptVault} from "../index";
import {ChildProcess} from "child_process";

import cryptvault = require('../');
var VaultDevServer = cryptvault.VaultDevServer;

import chai = require("chai");
import chaiAsPromised = require("chai-as-promised");
import ExpectStatic = Chai.ExpectStatic;
import {AuthDict} from "../vault";
import {AuthObj} from "../vault";
var expect:ExpectStatic = chai.expect;
chai.use(chaiAsPromised);

var vaultServer = new VaultDevServer();
var vault: CryptVault;
var testString = 'the quick brown fox';

describe('VaultDevServer', ()=> {
	before('start dev server', (done)=> {
		vaultServer.start()
			.then(()=> {
				vault = vaultServer.vault;
				done();
			})
			.catch((err:Error)=> {
				done(err);
			});
	});
	it('is unsealed', ()=> {
		return expect(vault.isSealed()).to.eventually.be.false;
	});
	it('is initialized', ()=> {
		return expect(vault.initialized()).to.eventually.be.true;
	});
	it('has transit mounted', ()=>{
		return expect(vault.isTransitMounted()).to.eventually.be.true;
	});
	it('gets status', (done)=>{
		vault.status().then((status:VaultStatus)=>{
			console.log("Vault status:",status);
			done();
		})
		.catch(done);
	});
	it('creates a new token and tests auth with it',()=>{
		return vault.createToken().then((auth:AuthObj)=>{
			var tmpVault:CryptVault = new cryptvault.CryptVault('',auth.client_token);
			return tmpVault.lookupAuth().then((authObj:any)=>{
				return expect(authObj.id).to.equal(auth.client_token);
			});
		});
	});
	it ('enables auth/app-id and then gets it from auths()', ()=>{;
		return vault.enableAuth('app-id')
		.then(()=>{
			return vault.authorizeApp('foobarbaz','foouser');
		})
		.then(()=>{
			var appVault:CryptVault = new cryptvault.CryptVault();
			return appVault.authenticateApp('foobarbaz','foouser').then((resp:AuthObj)=>{
				return expect(appVault.lookupAuth().then((auth:any)=>auth.id))
					.to.eventually.equal(resp.client_token);
			});
		});
	});
	it ('tests creating and renewing tokens',()=>{
		return vault.createToken().then((auth:AuthObj)=>{
			console.log("Created token:", auth);
			var appVault:CryptVault = new cryptvault.CryptVault("",auth.client_token);
			return appVault.renewToken()
			.then((token:any)=>{
				console.log("Renewed token", token);
				return expect(auth.client_token).to.be.a('string');
			})
			.then(()=>{
				return appVault.lookupAuth().then((auth:AuthObj)=>{
					console.log("AUTH", auth);
				});
			});
		});
	});
	it('adds new policy named foo, then checks that it is returned by policies(), then removes it',()=>{
		return vault.addPolicy('foo',{path:{
			'transit/keys/foo':{policy:'read'},
			'secret/*':{policy:'write'}
		}})
		.then(()=> {
			return vault.policies().then((policies:any)=> {
				console.log("policies:", policies);
				return expect(policies).to.contain('foo');
			});
		})
		.then(()=>{
			return vault.removePolicy('foo').then(()=>{
				console.log('policy removed');
				return this;
			});
		})
		.then(()=>{
			return vault.policies().then((policies:any)=> {
				console.log("policies:", policies);
				return expect(policies).to.not.contain('foo');
			});
		});
	});
	it('gets enabled auths', ()=>{
		return vault.auths().then((auths)=>{
			console.log("auths:", auths);
		});
	});
	it('encrypts and then decrypts test string', (done)=>{
		vault.encrypt('foo',testString)
		.then((cipherText:string)=>{
			console.log("cipher text:",cipherText);
			return(cipherText);
		})
		.then((cipherText:string)=>{
			return vault.decrypt('foo',cipherText);
		})
		.then((plainText)=>{
			console.log("Decrypted:", plainText);
			assert.equal(plainText,testString);
			done();
		})
		.catch(done);
	});
	it('disables app-id auth', (done)=>{
		vault.disableAuth('app-id').then(()=>{
			return vault.auths().then((auths:AuthDict)=>{
				expect(auths['app-id/']).to.be.undefined;
				done();
			});
		})
		.catch(done);
	});
	after('shutdown dev server',()=>{
		vaultServer.shutdown();
	});
});