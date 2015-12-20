import {Socket} from "net";
import Promise = Q.Promise;
export interface CryptoResponse {
	lease_id: string;
	renewable: boolean;
	lease_duration: number;
	data: any;
	warnings: any;
	auth: any;
}
export interface EncryptResult extends CryptoResponse {
	data: { ciphertext: string };
}
export interface DecryptResult extends CryptoResponse {
	data: { plaintext: string };
}
export interface VaultStatus {
	sealed:boolean;
	n:number;
	progress:number;
	t:number;
}
export interface Initialized {
	initialized:boolean;
}
export interface VaultOpts {
	json:{
		mount_point?:string,
		lease_id?:string;
		name?:string;
		policy?:string;
		type?:string,
		description?: string;
		rules?:any;
	}
}
export interface EnableAuthOpts {
	json: {
		type:string;
		mount_point:string;
		description?:string;
	}
}
export interface DisableAuthOpts {
	json: {
		mount_point:string;
	}
}
export interface CreateTokenOpts {
	policies:string[];
	ttl:string;
	display_name:string;
}
export interface RenewTokenOpts {
	increment:number;
}
export interface PolicyOpts {
	path: {[pathName:string]:{policy:string}};
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
export interface AddPolicyOpts {
	json: {
		rules: string;
		name:string;
	}
}
export interface RemovePolicyOpts {
	json: {
		name:string;
	}
}
export interface AuthObj {
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
	init(callback:(error:Error,response:any)=>any):void;
	seal(callback:(error:Error,response:any)=>any):void;
	unseal(callback:(error:Error,response:any)=>any):void;
	mounts(callback:(error:Error,response:any)=>any):void;
	mount(opts:VaultOpts, callback:(error:Error,response:any)=>void):void;
	//unmount(mount_point:string, callback:(error:Error,response:any)=>any):void;
	//remount(callback:(error:Error,response:any)=>any):any;
	addPolicy(opts:AddPolicyOpts,callback:(error:Error,response:any)=>any):void;
	removePolicy(opts:RemovePolicyOpts, callback:(error:Error)=>void):void;
	policies(callback:(error:Error,response:any)=>void):void;
	auths(callback:(error:Error,response:AuthDict)=>void):void;
	enableAuth(opts:EnableAuthOpts, callback:(error:Error,response:any,a?:any)=>void):void;
	disableAuth(opts:DisableAuthOpts, callback:(error:Error,response:any,a?:any)=>void):void;
}