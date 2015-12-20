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
import {AddPolicyOpts} from "../vault";
import {PolicyDict} from "../vault";
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
		return expect(vault.isInitialized()).to.eventually.be.true;
	});
	it('has transit mounted', ()=>{
		return expect(vault.isTransitMounted()).to.eventually.be.true;
	});
	it('tries to mount transit after already being mounted', ()=>{
		return expect(vault.mountTransit()).to.eventually.be.false;
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
	it ('enables auth/app-id and then gets it from auths()', ()=>{
		return vault.enableAuth('app-id')
		.then(()=>{
			return vault.authorizeApp('foobarbaz','foouser');
		})
		.then(()=>{ // test authentication
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
		return vault.writePolicy('foo',{
			'transit/keys/foo':{policy:'read'},
			'secret/*':{policy:'write'}
		})
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
	describe('tests synchronous functions',()=>{
		it('tests statusSync()',()=>{
			return expect(vault['statusSync']().sealed).to.be.false;
		});
		it('tests isSealedSync()',()=>{
			return expect(vault['isSealedSync']()).to.be.false;
		});
		it('tests isInitializedSync()', ()=> {
			return expect(vault['isInitializedSync']()).to.be.true;
		});
		it('tests mountTransitSync()',()=>{
			return expect(vault.mountTransitSync()).to.be.a('boolean');
		});
		it('tests isTransitMountedSync()',()=>{
			return expect(vault.isTransitMountedSync()).to.be.true;
		});
		it('tests get and write policies',()=>{
			console.log("Write policy:",vault.writePolicySync('foo',{
				'*':{policy:'deny'},
				'/mount/transit/foo':{policy:"write"}
			}));
			console.log("foo policy:",vault.getPolicySync('foo'));
			var token = vault.createTokenSync({policies:['foo']});
			console.log("TOKEN:",token);
		});
		it('tests enableAuthSync("github"), then checks result with authsSync()',()=>{
			expect(vault.enableAuthSync('github')).to.be.true;
			var auths = vault.authsSync();
			expect(auths['github/'].type).to.be.equal('github');
		});
		it('tests enableAuthSync("github") after already being enabled, then checks result with authsSync().',()=>{
			var auths = vault.authsSync();
			expect(auths['github/'].type).to.be.equal('github');
			expect(vault.enableAuthSync('github')).to.be.false;
		});
		it('tests disableAuthSync("github") after already being enabled, then checks result with authsSync().',()=>{
			var auths = vault.authsSync();
			expect(auths['github/']).to.be.an('object');
			var disableResult = vault.disableAuthSync('github');
			expect(disableResult).to.be.true;
			auths = vault.authsSync();
			expect(auths['github/']).to.be.undefined;
			expect(vault.disableAuthSync('github')).to.be.false;
		});
		it('tests addPolicySync(...), policiesSync(), getPolicySync(name), and removePoliciesSync(...)',()=>{
			var policy:PolicyDict = {
				'transit/keys/foo':{policy:'read'},
				'secret/*':{policy:'write'}
			};
			var result:any = vault.writePolicySync('foo',policy);
			expect(result).to.be.undefined;
			console.log(vault.getPolicySync('foo'));
			var policies = vault.policiesSync();
			expect(policies).to.contain('foo');
			policy['*']={policy:'deny'};
			result = vault.writePolicySync('foo',policy);
			expect(result).to.be.undefined;
			console.log(vault.getPolicySync('foo'));
			result = vault.getPolicySync('foo');
			expect(result.rules).to.be.a('string');
			console.log(result);
			result = vault.removePolicySync('foo');
			expect(result).to.be.undefined;
			policies = vault.policiesSync();
			expect(policies).to.not.contain('foo');
		});
		// TODO: Test that policies are enforced
		it('tests async encryption functions',()=>{
			var response = vault.createEncryptionKeySync('bar');
			console.log("Create encryption key response:", response);
			var key = vault.getEncryptionKeySync('bar');
			console.log("Get encryption key response:", key);
			var cipherText = vault.encryptSync('bar',testString);
			console.log("Encrypted:", cipherText);
			expect(cipherText).to.be.a('string');
			var decrypted = vault.decryptSync('bar', cipherText);
			console.log("Decrypted:", decrypted);
			expect(decrypted).to.be.equal(testString);
		});
		it('tests lookupAuthSync()',()=>{
			var auth = vault.lookupAuthSync();
			console.log("AUTH:", auth);
			expect(auth.id).to.be.a('string');
			expect(auth.id).to.be.equal(vault['_vault'].token);
		});
		it('tests authorizeAppSync(...) and authenticateAppSync(...)',()=>{
			vault.enableAuthSync('app-id');
			vault.authorizeAppSync("fooapp","foouser");
			var auth = vault.authenticateAppSync("fooapp","foouser");
			console.log("AUTH:", auth);
			expect(auth.client_token).to.be.a('string');
			expect(auth.lease_duration).to.be.a('number');
		});
	});
	after('shutdown dev server',()=>{
		vaultServer.shutdown();
	});
});