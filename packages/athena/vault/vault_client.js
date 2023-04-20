const axios = require('axios');

class VaultClient {

	constructor({
		url,
		apiVersion='v1',
		username,
		password,
		orgName,
		vaultPath
	}, logger) {
		this.username = username;
		this.password = password;
		this.logger = logger;
		this.token = '';
		this.isInitialized = false;
		this.vaultData = {};
		this.url = url;
		this.apiVersion = apiVersion;
		this.vaultIdentitiesPath = `${orgName}/data/${vaultPath}`;
		this.vaultFolderContentPath = `${orgName}/metadata/${vaultPath}`;
	}

	getIsInitialized() {
		return this.isInitialized;
	}

	async init() {
		const passwordObject = { password: this.password };
		await axios.post(`${this.url}/${this.apiVersion}/auth/userpass/login/${this.username}`,
			passwordObject
		)
			.then(res => {
				this.token = res.data.auth.client_token;
				this.isInitialized = true;
			})
			.catch((error) => {
				this.logger.error('Unable to login, an error has ocurred!', error.response.status);
				throw error;
			});
	}

	async listSecrets(isRetried=false) {
		return axios.get(`${this.url}/${this.apiVersion}/${this.vaultFolderContentPath}?list=true`,
			{ headers: { 'X-Vault-Token': this.token } })
			.then(res => res.data.data.keys)
			.catch(async (error) => {
				if (!isRetried && error && error.response && (error.response.status === 401 || error.response.status === 403)) {
					await this.init();
					return await this.listSecrets(true);
				}
				this.logger.error('Unable to list secrets!', error);
				throw error;
			});
	}

	async readSecret(secretName, isRetried=false) {
		return axios.get(`${this.url}/${this.apiVersion}/${this.vaultIdentitiesPath}/${secretName}`,
			{ headers: { 'X-Vault-Token': this.token } })
			.then(res => res.data.data.data)
			.catch(async (error) => {
				if (!isRetried && error && error.response && (error.response.status === 401 || error.response.status === 403)) {
					await this.init();
					return await this.readSecret(secretName, true);
				}
				this.logger.error('Unable to read secret!', error);
				throw error;
			});
	}

	async upsertSecret(secretName, data, isRetried=false) {
		return axios(
			{
				method: 'post',
				url: `${this.url}/${this.apiVersion}/${this.vaultIdentitiesPath}/${secretName}`,
				headers: { 'X-Vault-Token': this.token },
				data: { data }
			})
			.then(() => this.logger.debug('Successfully created!'))
			.catch(async (error) => {
				if (!isRetried && error && error.response && (error.response.status === 401 || error.response.status === 403)) {
					await this.init();
					return await this.upsertSecret(secretName, data, true);
				}
				this.logger.error('Unable to create secret!', error);
				throw error;
			});
	}
}

module.exports = VaultClient;
