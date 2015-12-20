import cv = require('./index');
import {Vault, VaultStatus, Initialized, VaultAuth, AuthDict, DisableAuthOpts, AppIdAuthOpts, AppUserIdAuthOpts, 
	PolicyOpts, AddPolicyOpts, AuthObj, AuthResponse, VaultOpts, EnableAuthOpts, RemovePolicyOpts, PoliciesResponse,
	CreateTokenOpts, RenewTokenOpts, DecryptOpts, EncryptOpts, CreateEncryptionKeyOpts, LookupAuthResponse, 
	AuthenticateAppOpts, InitOpts, InitResponse} from "./vault";

var vault = new cv.CryptVault("http://127.0.0.1:8237");
console.log("VAULT INITIALIZED:",vault.isInitializedSync());

var initResp:InitResponse = vault.initSync();
console.log("INIT KEYS:",initResp.keys);

for (var i=0;i<2;i++){
    console.log(vault.unsealSync(initResp.keys[i]));
    console.log("SEALED:",vault.isSealedSync());
}
console.log(vault.unsealSync(initResp.keys[0],true));
console.log("SEALED:",vault.isSealedSync());

for (var i=0;i<4;i++){
    console.log(vault.unsealSync(initResp.keys[i]));
    console.log("SEALED:",vault.isSealedSync());
}
console.log("SEALED:",vault.isSealedSync());