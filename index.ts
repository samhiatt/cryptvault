import {EncryptResult,DecryptResult,CryptoResponse} from "./vault";
var Base64 = require('js-base64').Base64;
var Q = require('q');
import cp = require('child_process');
var node_vault = require('node-vault');
import {error} from "util";
import {EventEmitter} from "events";
import {Vault, VaultStatus, Initialized, VaultAuth, AuthDict, DisableAuthOpts, AppIdAuthOpts, AppUserIdAuthOpts, 
	PolicyOpts, AddPolicyOpts, AuthObj, AuthResponse, VaultOpts, EnableAuthOpts, RemovePolicyOpts, PoliciesResponse,
	CreateTokenOpts, RenewTokenOpts, DecryptOpts, EncryptOpts, CreateEncryptionKeyOpts, LookupAuthResponse, 
	AuthenticateAppOpts} from "./vault";

export class CryptVault {
	protected _vault:Vault;
	constructor(
		vault_addr:string=process.env['VAULT_ADDR']||'http://127.0.0.1:8200',
		vault_token:string=process.env['VAULT_TOKEN']
	){
		this._vault = node_vault({endpoint:vault_addr,token:vault_token});
	}
	initialized():Q.Promise<boolean>{
		return Q.nbind(this._vault.initialized,this._vault)().then((resp:any)=>resp.initialized);
	}
	status():Q.Promise<VaultStatus>{
		return Q.nbind(this._vault.status,this._vault)();
	}
	isSealed():Q.Promise<boolean>{
		return this.status().then((status:VaultStatus)=>status.sealed);
	}
	mountTransit():Q.Promise<void>{
		var mountOpts:VaultOpts = {json:{mount_point:'transit',type:'transit'}};
		return Q.nbind(this._vault.mount,this._vault)(mountOpts);
	}
	isTransitMounted():Q.Promise<boolean>{
		return Q.nbind(this._vault.mounts,this._vault)().then((mounts:any)=>mounts.hasOwnProperty('transit/'));
	}
	enableAuth(authType:string, description:string="app-id/user-id based credentials"):Q.Promise<void>{
		var authOpts:EnableAuthOpts = {json:{
			mount_point:authType,
			type:authType,
			description: description
		}};
		return Q.nbind(this._vault.enableAuth, this._vault)(authOpts);
	}
	disableAuth(authType:string):Q.Promise<void>{
		var authOpts:DisableAuthOpts = {json:{mount_point:authType}};
		return Q.nbind(this._vault.disableAuth,this._vault)(authOpts);
	}
	auths():Q.Promise<AuthDict>{
		return Q.nbind(this._vault.auths,this._vault)();
	}
	addPolicy(name:string,policy:PolicyOpts):Q.Promise<void>{
		var policyOpts:AddPolicyOpts = {json:{
			name: name,
			rules:JSON.stringify(policy)
		}};
		return Q.nbind(this._vault.addPolicy,this._vault)(policyOpts);
	}
	removePolicy(name:string):Q.Promise<void>{
		var policyOpts:RemovePolicyOpts = {json:{ name: name }};
		return Q.nbind(this._vault.removePolicy,this._vault)(policyOpts);
	}
	policies():Q.Promise<any>{
		return Q.nbind(this._vault.policies,this._vault)().then((resp:PoliciesResponse)=>resp.policies);
	}
	createToken():Q.Promise<any>{
		var opts:CreateTokenOpts = {policies:['default'],ttl:'1h',display_name:'default token'};
		return Q.nbind(this._vault.write,this._vault)("auth/token/create", opts)
			.then((resp:AuthResponse)=>resp.auth);
	}
	renewToken():Q.Promise<AuthObj>{
		var opts:RenewTokenOpts = {increment:3600};
		return Q.nbind(this._vault.write,this._vault)("auth/token/renew-self", opts)
			.then((resp:AuthResponse)=>resp.auth);
	}
	authorizeApp(appId:string,userId:string,cidrBlock:string="127.0.0.0/16",displayName:string=""):Q.Promise<any>{
		return this.auths().then((auths:AuthDict)=>{
			if (auths.hasOwnProperty('app-id/')) {
				var appOpts:AppIdAuthOpts = {
					value: 'default',
					display_name: displayName
				};
				return Q.nbind(this._vault.write,this._vault)("auth/app-id/map/app-id/"+appId, appOpts).then(()=>{
					var userOpts:AppUserIdAuthOpts = {
						value: appId,
						cidr_block: cidrBlock
					};
					return Q.nbind(this._vault.write, this._vault)("auth/app-id/map/user-id/"+userId, userOpts);
				});
			}
			else throw new Error("app-id backend not mounted.");
		});
	}
	authenticateApp(appId:string,userId:string):Q.Promise<AuthObj>{
		var opts:AuthenticateAppOpts = {user_id:userId,app_id:appId};
		return Q.nbind(this._vault.write,this._vault)("auth/app-id/login",opts)
			.then((resp:AuthResponse)=>{
				this._vault = new CryptVault(this._vault.endpoint,resp.auth.client_token)._vault;
				return resp.auth;
			});
	}
	lookupAuth():Q.Promise<AuthObj>{
		return Q.nbind(this._vault.read,this._vault)('auth/token/lookup-self',{})
			.then((result:LookupAuthResponse)=>result.data);
	}
	createEncryptionKey(keyName:string):Q.Promise<any>{
		var opts:CreateEncryptionKeyOpts = {value:true};
		return Q.nbind(this._vault.write,this._vault)('transit/keys/'+keyName,opts);
	}
	encrypt(keyName:string, plaintext:string):Q.Promise<string>{
		var opts:EncryptOpts = {plaintext: Base64.encode(plaintext)};
		return Q.nbind(this._vault.write,this._vault)('transit/encrypt/'+keyName,opts)
			.then((result:EncryptResult)=>result.data.ciphertext);
	}
	decrypt(keyName:string, ciphertext:string):Q.Promise<string>{
		var opts:DecryptOpts = {ciphertext:ciphertext};
		return Q.nbind(this._vault.write,this._vault)('transit/decrypt/'+keyName,opts)
			.then((result:DecryptResult)=>Base64.decode(result.data.plaintext));
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
		this._events.on('close',(data:any)=>{
			//console.log("close event fired with data:",data);
			if (typeof this.onClose == 'function') this.onClose();
		});
		this._events.on('started',()=>{
			//console.log("");
			//this.state = 'running';
		});
		this._events.on('data',(data:string)=>{
			//console.log("DATA:",data);
		});
		this.on = this._events.on;
	}
	start():Q.Promise<void>{
		return Q.Promise((resolve:()=>{},reject:(err:Error)=>{})=>{
			if (this._vaultProcess) {
				if (this.state=='starting') this._events.once('started',()=>{
					resolve();
				});
				if (this.state=='running') resolve();
			}
			this.state='starting';
			this._vaultProcess = cp.exec('vault server -dev');//, (err:Error,result:Buffer)=>{
			this._vaultProcess.on('error',(err:Error)=>{
				this._vaultProcess.kill("SIGTERM");
				reject(err);
			});
			this._vaultProcess.on('close',(exitCode:number)=>{
				this.state = 'closed';
				this._events.emit('close', exitCode);
				if (exitCode!=0) {
					//reject(new Error("Vault exited with code "+exitCode));
					reject(new Error(this._stderr));
				}
			});
			this._vaultProcess.stdout.on('data',(data:string)=>{
				//console.log("dev server started",data);
				this._events.emit('data',data);
				var tokenMatch = /Root Token: (\S+)/.exec(data);
				var unsealKeyMatch = /Unseal Key: (\S+)/.exec(data);
				if (!tokenMatch || !unsealKeyMatch) {
					if (!this._token) reject(new Error("Error parsing credentials from response."));
				}
				else {
					this._token = tokenMatch[1];
					this.vault = new CryptVault("http://127.0.0.1:8200", this._token);
					// Wait for a second to make sure the port isn't in use
					setTimeout(()=> {
						this.vault.mountTransit().then(()=>{
							this._events.emit('started');
							this.state='running';
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
