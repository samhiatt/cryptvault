import {EncryptResult,DecryptResult,CryptoResponse} from "./vault";
var Base64 = require('js-base64').Base64;
var Q = require('q');
import cp = require('child_process');
import {Vault} from "./vault";
var node_vault = require('node-vault');
import {error} from "util";
import {EventEmitter} from "events";
import {VaultStatus} from "./vault";
import {Initialized} from "./vault";
import {VaultAuth} from "./vault";
import {AuthDict} from "./vault";
import {DisableAuthOpts} from "./vault";
import {AppIdAuthOpts} from "./vault";
import {AppUserIdAuthOpts} from "./vault";
import {PolicyOpts} from "./vault";
import {AddPolicyOpts} from "./vault";
import {AuthObj} from "./vault";
import {AuthResponse} from "./vault";

export class CryptVault {
	protected _vault:Vault;
	constructor(
		vault_addr:string=process.env['VAULT_ADDR']||'http://127.0.0.1:8200',
		vault_token:string=process.env['VAULT_TOKEN']
	){
		this._vault = node_vault({endpoint:vault_addr,token:vault_token});
	}
	initialized():Q.Promise<boolean>{
		return Q.Promise((resolve:(initialized:boolean)=>{},reject:(err:Error)=>{})=>{
			this._vault.initialized((err:Error,initialized:Initialized)=>{
				if (err) reject(err);
				else {
					resolve(initialized.initialized);
				}
			});
		});
	}
	status():Q.Promise<VaultStatus>{
		return Q.Promise((resolve:(status:VaultStatus)=>{},reject:(err:Error)=>{})=>{
			this._vault.status((err:Error,status:VaultStatus)=>{
				if (err) reject(err);
				else resolve(status);
			});
		});
	}
	isSealed():Q.Promise<boolean>{
		return this.status().then((status:VaultStatus)=>{
			return status.sealed;
		});
	}
	mountTransit():Q.Promise<void>{
		return Q.Promise((resolve:()=>{},reject:(err:Error)=>{})=>{
			this._vault.mount({json:{mount_point:'transit',type:'transit'}},(err:Error)=>{
				if (err) reject(err);
				else resolve();
			});
		});
	}
	isTransitMounted():Q.Promise<boolean>{
		return Q.Promise((resolve:(transitMounted:boolean)=>{},reject:(err:Error)=>{})=>{
			this._vault.mounts((err:Error,resp:any)=>{
				if (err) reject(err);
				else resolve(resp.hasOwnProperty('transit/'));
			});
		});
	}
	enableAuth(authType:string, description:string="app-id/user-id based credentials"):Q.Promise<void>{
		return Q.Promise((resolve:()=>{},reject:(err:Error)=>{})=>{
			this._vault.enableAuth({
				json:{
					mount_point:authType,
					type:authType,
					description: description
				}
			},(err:Error,resp:any,a:any)=>{
				if (err) reject(err);
				else resolve();
			});
		});
	}
	disableAuth(authType:string):Q.Promise<void>{
		return Q.Promise((resolve:()=>{},reject:(err:Error)=>{})=>{
			var authOpts: DisableAuthOpts = {json:{mount_point:authType}};
			this._vault.disableAuth(authOpts,(err:Error)=>{
				if (err) reject(err);
				else resolve();
			});
		});
	}
	auths():Q.Promise<AuthDict>{
		return Q.Promise((resolve:(auth:AuthDict)=>{},reject:(err:Error)=>{})=>{
			this._vault.auths((err:Error, resp:AuthDict)=>{
				if (err) reject(err);
				else resolve(resp);
			});
		});
	}
	addPolicy(name:string,policy:PolicyOpts):Q.Promise<void>{
		return Q.Promise((resolve:(resp:any)=>{},reject:(err:Error)=>{})=>{
			var policyOpts:AddPolicyOpts={
				json:{
					name: name,
					rules:JSON.stringify(policy)
				}
			};
			this._vault.addPolicy(policyOpts,(err:Error, resp:any)=>{
				if (err) reject(err);
				else resolve(resp);
			});
		});
	}
	removePolicy(name:string):Q.Promise<void>{
		return Q.Promise((resolve:()=>{},reject:(err:Error)=>{})=>{
			this._vault.removePolicy({json:{name:name}},(err:Error)=>{
				if (err) reject(err);
				else resolve();
			});			
		});
	}
	policies():Q.Promise<any>{
		return Q.Promise((resolve:(policies:string[])=>{},reject:(err:Error)=>{})=>{
			this._vault.policies((err:Error, resp:{policies:string[]})=>{
				if (err) reject(err);
				else resolve(resp.policies);
			});
		});
	}
	createToken():Q.Promise<any>{
		return Q.Promise((resolve:(auth:AuthObj)=>{},reject:(err:Error)=>{})=>{
			var self = this;
			var opts = {policies:['default'],ttl:'1h',display_name:'default token'};
			this._vault.write("auth/token/create", opts, (err:Error, resp:AuthResponse)=>{
				if (err) reject(err);
				resolve(resp.auth);
			});
		});
	}
	renewToken():Q.Promise<AuthObj>{
		return Q.Promise((resolve:(auth:AuthObj)=>{},reject:(err:Error)=>{})=>{
			var self = this;
			this._vault.write("auth/token/renew-self",{increment:3600},(err:Error,resp:AuthResponse)=>{
				if (err) reject(err);
				else {
					//self._vault = new CryptVault(self._vault.endpoint,resp.auth.client_token)._vault;
					self._vault.token = resp.auth.client_token;
					resolve(resp.auth);
				}
			});
		});
	}
	authorizeApp(appId:string,userId:string,cidrBlock:string="127.0.0.0/16",displayName:string=""):Q.Promise<any>{
		return Q.Promise((resolve:()=>{},reject:(err:Error)=>{})=>{
			var self = this;
			this.auths().then((auths:AuthDict)=>{
				if (auths.hasOwnProperty('app-id/')) {
					var opts:AppIdAuthOpts = {
						value: 'default',
						display_name: displayName
					};
					self._vault.write("auth/app-id/map/app-id/"+appId, opts, (err:Error)=>{
						if (err) reject(err);
						var userOpts:AppUserIdAuthOpts = {
							value: appId,
							cidr_block: cidrBlock
						};
						self._vault.write("auth/app-id/map/user-id/"+userId, userOpts, (err:Error)=>{
							if (err) reject(err);
							else resolve();
						});
					});
				}
				else reject(new Error("app-id backend not mounted."));
			});
		});
	}
	authenticateApp(appId:string,userId:string):Q.Promise<AuthObj>{
		return Q.Promise((resolve:(auth:AuthObj)=>{},reject:(err:Error)=>{})=>{
			this._vault.write("auth/app-id/login",{user_id:userId,app_id:appId},(err:Error,resp:AuthResponse)=>{
				if (err) reject(err);
				else {
					this._vault = new CryptVault(this._vault.endpoint,resp.auth.client_token)._vault;
					resolve(resp.auth);
				}
			});
		});
	}
	lookupAuth():Q.Promise<AuthObj>{
		return Q.Promise((resolve:(auth:AuthObj)=>{},reject:(err:Error)=>{})=>{
			this._vault.read("auth/token/lookup-self",{},(err:Error,resp:any)=>{
				if (err) reject(err);
				else resolve(resp.data);
			});
		});
	}
	createEncryptionKey(keyName:string):Q.Promise<any>{
		return Q.Promise((resolve:(result:CryptoResponse)=>{},reject:(err:Error)=>{})=>{
			this._vault.write('transit/keys/'+keyName,{value:true},(err:Error,result:CryptoResponse)=>{
				if (err) reject(err);
				else {
					resolve(result);
				}
			});
		});
	}
	encrypt(keyName:string, plaintext:string):Q.Promise<string>{
		return Q.Promise((resolve:(cipherText:string)=>{},reject:(err:Error)=>{})=>{
			this._vault.write(
				'transit/encrypt/'+keyName,
				{plaintext: Base64.encode(plaintext)},
				(err:Error,result:EncryptResult)=>{
					if (err) reject(err);
					else {
						resolve(result.data.ciphertext);
					}
				}
			);
		});
	}
	decrypt(keyName:string, ciphertext:string):Q.Promise<string>{
		return Q.Promise((resolve:(plainText:string)=>{},reject:(err:Error)=>{})=>{
			this._vault.write(
				'transit/decrypt/'+keyName,
				{ciphertext:ciphertext},
				(err:Error,result:DecryptResult)=>{
					if (err) reject(err);
					else {
						resolve(Base64.decode(result.data.plaintext));
					}
				}
			);
		});
	}
}

export class VaultDevServer {
	private _vaultProcess:cp.ChildProcess;
	private _events = new EventEmitter();
	private _token:string;
	private _stderr:string="";
	on:(event:string, listener:Function)=>EventEmitter;
	vault:CryptVault;
	state:string='closed';
	onClose:()=>void;
	constructor(){
		var self = this;
		this._events.on('close',(data:any)=>{
			//console.log("close event fired with data:",data);
			if (typeof self.onClose == 'function') self.onClose();
		});
		this._events.on('started',()=>{
			//console.log("");
			//self.state = 'running';
		});
		this._events.on('data',(data:string)=>{
			//console.log("DATA:",data);
		});
		this.on = this._events.on;
	}
	start():Q.Promise<void>{
		return Q.Promise((resolve:()=>{},reject:(err:Error)=>{})=>{
			var self = this;
			if (this._vaultProcess) {
				if (self.state=='starting') self._events.once('started',()=>{
					resolve();
				});
				if (self.state=='running') resolve();
			}
			this.state='starting';
			this._vaultProcess = cp.exec('vault server -dev');//, (err:Error,result:Buffer)=>{
			this._vaultProcess.on('error',(err:Error)=>{
				this._vaultProcess.kill("SIGTERM");
				reject(err);
			});
			this._vaultProcess.on('close',(exitCode:number)=>{
				self.state = 'closed';
				self._events.emit('close', exitCode);
				if (exitCode!=0) {
					//reject(new Error("Vault exited with code "+exitCode));
					reject(new Error(this._stderr));
				}
			});
			this._vaultProcess.stdout.on('data',(data:string)=>{
				//console.log("dev server started",data);
				self._events.emit('data',data);
				var tokenMatch = /Root Token: (\S+)/.exec(data);
				var unsealKeyMatch = /Unseal Key: (\S+)/.exec(data);
				if (!tokenMatch || !unsealKeyMatch) {
					if (!self._token) reject(new Error("Error parsing credentials from response."));
				}
				else {
					self._token = tokenMatch[1];
					self.vault = new CryptVault("http://127.0.0.1:8200", self._token);
					// Wait for a second to make sure the port isn't in use
					setTimeout(()=> {
						self.vault.mountTransit().then(()=>{
							self._events.emit('started');
							self.state='running';
							resolve();
						}).catch((err:Error)=>{
							reject(err);
						});
					}, 1000);
				}
			});
			this._vaultProcess.stderr.on('data',(data:string)=>{
				this._stderr += data;
				//if (/bind: address already in use/.exec(data)) reject(new Error(data));
			});
		});
	}
	shutdown():void{
		this._vaultProcess.kill("SIGTERM");
	}
}
