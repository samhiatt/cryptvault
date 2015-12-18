export interface VaultResponse {
	lease_id: string;
	renewable: boolean;
	lease_duration: number;
	data: any;
	warnings: any;
	auth: any;
}
export interface EncryptResult extends VaultResponse {
	data: { ciphertext: string };
}
export interface DecryptResult extends VaultResponse {
	data: { plaintext: string };
}