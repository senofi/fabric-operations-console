import { RestApi } from '../rest/RestApi';

class VaultIdentityStorage {
	async save(key, data) {
		let url = '/api/v3/vault/identity';

		return await RestApi.put(url, data);
	}

	async get() {
		let url = '/api/v3/vault/identity';
		const results = await RestApi.get(url);
		return results;
	}

	async removeIdentity(name) {
		throw new Error('Operation "remove identity" is not supported by VaultIdentityStorage.');
	}

	canRemoveIdentity() {
		return false;
	}
}

export default VaultIdentityStorage;
