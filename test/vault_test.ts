import Promise = Q.Promise;
import {AuthDict, VaultStatus, AuthObj, AddPolicyOpts, PolicyRules, EncryptKey, PolicyObject, TokenObj } 
	from "../vault";
import {CryptVault} from "../index";
import {ChildProcess} from "child_process";

import cryptvault = require('../');

import fs = require('fs');
import chai = require("chai");
import chaiAsPromised = require("chai-as-promised");
var expect:Chai.ExpectStatic = chai.expect;
chai.use(chaiAsPromised);

var vaultServer = new cryptvault.VaultDevServer();
var vault: CryptVault;
var testString = 'the quick brown fox';

describe('Vault', ()=> {
	before('start VaultDevServer', (done)=> {
		vaultServer.start()
			.then(()=> {
				vault = vaultServer.vault;
				done();
			})
			.catch((err:Error)=> {
				done(err);
			});
	});
	describe('async promise-returning methods',()=>{
		describe('isSealed()', ()=> {
			it('resolves to false', ()=> {
				return expect(vault.isSealed()).to.eventually.be.false;
			});
		});
		describe('isInitialized()', ()=> {
			it('resolves to true', ()=> {
				return expect(vault.isInitialized()).to.eventually.be.true;
			});
		});
		describe('isTransitMounted()', ()=>{
			it('resolves to true', ()=> {
				return expect(vault.isTransitMounted()).to.eventually.be.true;
			});
		});
		describe('mountTransit()', ()=> {
			it('resolves to false since it is already mounted', ()=> {
				return expect(vault.mountTransit()).to.eventually.be.false;
			});
		});
		describe('status()',()=>{
			it('resolves to a status with sealed=false', ()=>{
				return expect(vault.status()).to.eventually.have.deep.property('sealed',false);
			});
			it('resolves to a status with progress=0', ()=>{
				return expect(vault.status()).to.eventually.have.deep.property('progress',0);
			});
		});
		describe("app-id auth methods",()=> {
			describe('auths()', ()=> {
				it('gets enabled auths, shoult contain token/', ()=> {
					return expect(vault.auths().then((auths)=> {
						console.log("auths:", auths);
						return auths;
					})).to.eventually.haveOwnProperty('token/');
				});
			});
			describe("enableAuth('app-id')",()=> {
				it('enables auth/app-id', ()=> {
					return expect(vault.enableAuth('app-id')).to.eventually.be.fulfilled;
				});
			});
			describe("authorizeApp(..)",()=> {
				it('authorizes app', ()=> {
					return expect(vault.authorizeApp('foobarbaz', 'foouser')).to.eventually.be.fulfilled;
				});
			});
			describe("authenticateApp(..)",()=>{
				var tmpVault:CryptVault = new cryptvault.CryptVault();
				it("resolves to an AuthObj with a new client_token",()=> {
					return expect(tmpVault.authenticateApp('foobarbaz', 'foouser').then((resp:AuthObj)=> {
						console.log("app-id auth obj:", resp);
						tmpVault = new cryptvault.CryptVault(null, resp.client_token);
						return resp.client_token;
					})).to.eventually.be.a('string');
				});
				it("tests authentication with new token",()=>{
					return expect(tmpVault.lookupAuth().then((auth:TokenObj)=>auth.id))
						.to.eventually.be.a('string');
				});
			});
			describe("disablesAuth('app-id')", ()=>{
				it('disables app-id authentication',()=>{
					return expect(vault.disableAuth('app-id')).to.eventually.be.fulfilled;
				});
				it('checks that it is not longer returned by auths()',()=>{
					return expect(vault.auths()).to.eventually.not.haveOwnProperty('app-id/');
				});
			});
		});
		describe("policy methods",()=> {
			var newPolicyDict: PolicyRules = { path: {
				'transit/keys/foo': {policy: 'read'},
				'secret/*': {policy: 'write'}
			}};
			describe("writePolicy('foo', newPolicyDict)",()=> {
				it("resolves to undefined", ()=> {
					return expect(vault.writePolicy('foo', newPolicyDict)).to.eventually.be.undefined;
				});
			});
			describe("policies()",()=> {
				it("resolves to an array that contains 'foo'", ()=> {
					return expect(vault.policies()).to.eventually.contain('foo');
				});
			});
			describe("getPolicy('foo')",()=> {
				it("resolves to a policy dicy", ()=> {
					return expect(vault.getPolicy('foo').then(policy=>{
						console.log(policy);
						return policy.rules;
					})).to.eventually.equal(JSON.stringify(newPolicyDict));
				});
			});
			describe("removePolicy('foo')",()=> {
				it("resolves to a policy dicy", ()=> {
					return expect(vault.removePolicy('foo')).to.eventually.be.undefined;
				});
			});
		});
		describe("token methods",()=> {
			var tmpVault:CryptVault;
			describe("createToken()",()=> {
				it("resolves to an AuthObj with renewable=true and sets up new tmpVault", ()=> {
					return expect(vault.createToken().then((authResp:AuthObj)=> {
						console.log("Created token:", authResp);
						tmpVault = new cryptvault.CryptVault(null, authResp.client_token);
						return authResp.renewable;
					})).to.eventually.be.true;
				});
			});
			describe("lookupAuth() with new token",()=>{
				it('new token has default policy',()=>{
					return expect(tmpVault.lookupAuth().then((lookupResp:TokenObj)=>{
						console.log("lookup resp",lookupResp);
						return lookupResp.policies;
					})).to.eventually.contain('default');
				});
			});
			describe("renewToken()",()=>{
				it('resolves to a renewed token with a lease duration of 1 hr',()=>{
					return expect(tmpVault.renewToken().then((resp:AuthObj)=>{
						console.log("Renew token response",resp);
						return resp.lease_duration;
					})).to.eventually.equal(3600);
				});
			});
		});
		describe('encrypt/decrypt methods', ()=> {
			var cipherText:string;
			describe("encrypt('foo',testString)", ()=> {
				it('encrypts the test string', ()=> {
					return expect(vault.encrypt('foo', testString).then((resp:string)=>{
						console.log("encrypt result:", resp);
						cipherText = resp;
					})).to.eventually.be.fulfilled;
				});
			});
			describe("decrypt('foo',cipherText)", ()=> {
				it('decrypts the cipher text, resolves to the original test string', ()=> {
					return expect(vault.decrypt('foo', cipherText)).to.eventually.equal(testString);
				});
			});
		});
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
			console.log("Write policy:",vault.writePolicySync('foo',
				//'path "transit/keys/foo" { policy = "write" } path "secret/foo/*" {policy="write"} '
				{ path: {
					'transit/decrypt/foo': {policy: "write"},
					'transit/encrypt/foo': {policy: "write"},
					'secret/foo/*': {policy: "write"},
					//'*': {policy: 'deny'}
				}}
			));
			console.log("foo policy:",vault.getPolicySync('foo'));
			console.log("default policy:",vault.getPolicySync('default'));
			var token = vault.createTokenSync({policies:['foo']});
			console.log("TOKEN:",token);
			//vault['_vault'].token=token.client_token;
			//console.log("AUTH LOOKUP:",vault.lookupAuthSync());
			//console.log("Renewed token:",vault.renewTokenSync());
			//expect(vault.createEncryptionKeySync('foo')).to.be.a('boolean');
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
			var policy:PolicyRules = { path: {
				'transit/keys/foo':{policy:'read'},
				'secret/*':{policy:'write'}
			}};
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
			vault.createEncryptionKeySync('bar');
			var key:EncryptKey = vault.getEncryptionKeySync('bar');
			console.log("Get encryption key response:", key);
			expect(key.data).to.be.an('object');
			expect(key.data.cipher_mode).to.equal('aes-gcm');
			expect(key.data.keys['1']).to.be.a('number');
			var cipherText:string = vault.encryptSync('bar',testString);
			console.log("Encrypted:", cipherText);
			expect(cipherText).to.be.a('string');
			var decrypted:string = vault.decryptSync('bar', cipherText);
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