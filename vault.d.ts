import {Socket} from "net";
import Promise = Q.Promise;
export interface VaultResponse {
	lease_id: string;
	renewable: boolean;
	lease_duration: number;
	data: any;
	warnings: any;
	auth: any;
}
export interface InitOpts {
	secret_shares:number;
	secret_threshold:number;
}
export interface InitResponse {
	keys: string[];
}
export interface UnsealOpts {
	key:string;
	reset?:boolean;
}
export interface UnsealResponse { 
	sealed: boolean; 
	t: number; 
	n: number; 
	progress: number;
}
export interface EncryptResult extends VaultResponse {
	data: { ciphertext: string };
}
export interface DecryptResult extends VaultResponse {
	data: { plaintext: string };
}
export interface EncryptKey extends VaultResponse {
	data: {
		name:string;
		cipher_mode: string;
		deletion_allowed: boolean;
		derived: boolean;
		keys:{[key:string]:number};
		min_decryption_version: number;
	}
}
export interface VaultStatus {
	sealed:boolean;
	n:number; //total number of keys
	progress:number;
	t:number; //threshold
}
export interface Initialized {
	initialized:boolean;
}
export interface MountOpts {
	type?:string;
	mount_point:string;
	description?:string;
}
export interface EnableAuthOpts extends MountOpts {
	type:string;
	mount_point:string;
}
export interface DisableAuthOpts extends MountOpts {
	mount_point:string;
}
export interface CreateTokenOpts {
	policies:string[];
	ttl?:string;
	display_name?:string;
}
export interface RenewTokenOpts {
	increment:number;
}
export interface TokenResponse {
	token:string;
	token_duration:string;
	token_renewable:boolean;
	token_policies:string[];
}
export interface PoliciesResponse {
	policies: string[];
}
export interface DecryptOpts {
	ciphertext: string;
}
export interface EncryptOpts {
	plaintext: string;
}
export interface LookupAuthResponse {
	data: any;
}
export interface CreateEncryptionKeyOpts {
	value:boolean;
}
export interface PolicyDict {[pathName:string]:{policy:string}}
export interface PolicyOpts {
	rules?: string;
	name:string;
}
export interface AddPolicyOpts {
	rules: string;
	name:string;
}
export interface AuthObj {
	id:string;
	client_token:string;
	lease_duration:number;
	metadata:any;
	policies:string[];
	renewable:boolean;
}
export interface AuthenticateAppOpts {
	user_id:string;
	app_id:string;
}
export interface AuthResponse {
	auth: AuthObj
}
export interface AppIdAuthOpts {
	value:string;
	display_name?:string;
}
export interface AppUserIdAuthOpts {
	value:string;
	cidr_block?:string;
}
export interface VaultAuth{
	description:string;
	type:string;
}
export interface AuthDict {[authType:string]:VaultAuth}
export interface Vault {
	token:string;
	endpoint:string;
	apiVersion:string;
	help(path:string, opts:any, callback:(error:Error,response:any)=>any):void;
	write(path:string, opts:any, callback:(error:Error,response:any)=>any):void;
	read(path:string, opts:any, callback:(error:Error,response:any)=>any):void;
	delete(path:string, opts:any, callback:(error:Error,response:any)=>any):void;
	status(callback:(error:Error,response:any,status:VaultStatus)=>any):void;
	initialized(callback:(error:Error,response:Initialized)=>any):void;
	init(opts:{json:InitOpts},callback:(error:Error,response:InitResponse)=>any):void;
	seal(callback:(error:Error,response:any)=>any):void;
	unseal(callback:(error:Error,response:any)=>any):void;
	mounts(callback:(error:Error,response:any)=>any):void;
	mount(opts:any, callback:(error:Error,response:any)=>void):void;
	//unmount(mount_point:string, callback:(error:Error,response:any)=>any):void;
	//remount(callback:(error:Error,response:any)=>any):any;
	addPolicy(opts:AddPolicyOpts,callback:(error:Error,response:any)=>any):void;
	//getPolicy(opts:AddPolicyOpts,callback:(error:Error,response:any)=>any):void;
	removePolicy(opts:PolicyOpts, callback:(error:Error)=>void):void;
	policies(callback:(error:Error,response:any)=>void):void;
	auths(callback:(error:Error,response:AuthDict)=>void):void;
	enableAuth(opts:EnableAuthOpts, callback:(error:Error,response:any,a?:any)=>void):void;
	disableAuth(opts:DisableAuthOpts, callback:(error:Error,response:any,a?:any)=>void):void;
}