const VaultClient = require('../vault/vault_client');

module.exports = function (logger, ev, t) {
	const app = t.express.Router();

	let vaultData = {};
	try {
		vaultData = require('/server/conf/vault/vault-config.json');
	} catch (error) {
		logger.error('Error while loading Vault configuration file! Error: ', error);
	}

	// Vault initialisation
	const vaultClient = new VaultClient(vaultData, logger);
	vaultClient.init();

	// Check if Vault client initialised middleware
	const checkIfVaultInitialisedMiddleware = (req, res, next) => {
		if (vaultClient.getIsInitialized()) {
			return next();
		}
		const msg = 'Vault client not initialised!';
		logger.error(msg);
		return res.status(404).json({
			msg,
			reason:
			'Vault client is not initialised. This could be due failed login, failed initialisation, wrong Vault url, Vault server down, etc.'
		});
	};

	// Extracted logic to get identity secret from Vault by name.
	const getIdentitySecretByName = async (name) => {
		const secret = await vaultClient
			.readSecret(name);

		const {
			data,
			id,
			peers = '[]',
			orderer = '[]',
			cas = '[]',
			tls_cas = '[]'
		} = secret;
		const credentialsData = JSON.parse(data);

		const { credentials, mspId: msp_id } = credentialsData;
		const { certificate, privateKey: private_key } = credentials;

		const certBuffer = Buffer.from(certificate);
		const privateKeyBuffer = Buffer.from(private_key);

		const identity = {};
		identity[id] = {
			cert: certBuffer.toString('base64'),
			private_key: privateKeyBuffer.toString('base64'),
			msp_id,
			peers: JSON.parse(peers),
			orderer: JSON.parse(orderer),
			cas: JSON.parse(cas),
			tls_cas: JSON.parse(tls_cas)
		};
		return identity;
	};

	// Definition of requests handling functions
	const getIdentitySecretByNameHandler = async (req, res) => {
		const name = req.params.name;
		let identity;
		try {
			identity = await getIdentitySecretByName(name);
		} catch (error) {
			const msg = `Error while fetching identity with key ${name} from Vault!`;
			logger.error(`${msg} Error: ${error}`);
			res.status(t.ot_misc.get_code(error)).json({
				msg,
				reason: error
			});
			return;
		}
		res.json(identity);
	};

	const getAllIdentitiesFromVaultHandler = async (req, res) => {
		let secretsNames = [];

		try {
			secretsNames = await vaultClient
				.listSecrets();
		} catch (error) {
			if (error && error.response && error.response.status === 404) {
				logger.warn(`No identities' secrets names were found! Error ${error}`);
			} else {
				const msg = 'Error while fetching identities\' secrets names from Vault!';
				logger.error(`${msg} Error: ${error}`);
				res.status(t.ot_misc.get_code(error)).json({
					msg,
					reason: error
				});
				return;
			}
		}

		secretsNames = secretsNames.filter((e) => e[e.length - 1] !== '/');

		let secrets = {};
		try {
			for (const secretName of secretsNames) {
				const secret = await getIdentitySecretByName(secretName);
				secrets = { ...secrets, ...secret };
			}
		} catch (error) {
			const msg = 'Error while fetching/parsing identities from Vault!';
			logger.error(`${msg} Error: ${error}`);
			res.status(t.ot_misc.get_code(error)).json({
				msg,
				reason: error
			});
			return;
		}

		res.json(secrets);
	};

	const upsertIdentitiesToVaultHandler = async (req, res) => {
		if (!req.body) {
			return res
				.status(400)
				.json(t.validate.fmt_input_error(req, [{ key: 'missing_type' }]));
		}

		const identities = req.body;
		const errors = [];

		for (let key in identities) {
			const identityValue = identities[key];
			let {
				cert,
				private_key,
				peers = [],
				orderer = [],
				cas = [],
				tls_cas = [],
				msp_id = ''
			} = identityValue;

			let msp_id = '';

			if (orderer && orderer.length) {
				const ordererId = orderer[0];
				const ordererIdParts = ordererId.split('.');
				if (ordererIdParts.length === 1) {
					msp_id = ordererIdParts[0];
				} else if (ordererIdParts.length === 2) {
					msp_id = ordererIdParts[1];
				}
			}

			if (!msp_id) {
				const componentsIds = [...peers];

				const mspIdsMapPromise = new Promise((resolve, reject) => {
					t.component_lib.get_msp_ids_by_ids(
						req,
						componentsIds,
						(err, mspIdsMap) => {
							if (err) {
								reject(err);
							} else {
								resolve(mspIdsMap);
							}
						}
					);
				});

				const mspIdsMap = await mspIdsMapPromise.then((res) => res);
				msp_id = Object.values(mspIdsMap).length === 0
					? ''
					: Object.values(mspIdsMap)[0];
			}

			const ca_root_certs = [];
			const tls_ca_root_certs = [];
			if (msp_id) {
				const mspMapPromise = new Promise((resolve, reject) => {
					t.component_lib.get_msp_by_msp_id(req, [msp_id], (err, msps) => {
						if (err) {
							reject(err);
						} else {
							resolve(msps);
						}
					});
				});

				const mspMap = await mspMapPromise.then((res) => res);
				const msp = mspMap[msp_id];

				if (msp) {
					if (msp.root_certs) {
						ca_root_certs.push(...msp.root_certs);
					}

					if (msp.tls_root_certs) {
						tls_ca_root_certs.push(...msp.tls_root_certs);
					}
				}
			}

			const bufferCert = Buffer.from(cert, 'base64');
			const bufferPrivateKey = Buffer.from(private_key, 'base64');
			const data = {
				credentials: {
					certificate: bufferCert.toString('utf-8'),
					privateKey: bufferPrivateKey.toString('utf-8')
				},
				mspId: msp_id,
				type: 'X.509'
			};
			const secretIdentity = {
				data: JSON.stringify(data),
				id: key,
				peers: JSON.stringify(peers),
				orderer: JSON.stringify(orderer),
				cas: JSON.stringify(cas),
				tls_cas: JSON.stringify(tls_cas),
				ca_root_certs: JSON.stringify(ca_root_certs),
				tlsca_root_certs: JSON.stringify(tls_ca_root_certs)
			};

			await vaultClient
				.upsertSecret(key, secretIdentity)
				.catch((e) => {
					errors.push(key);
				});
		}

		res.status(200).json({ errors });
	};

	// Routes definition
	app.get(
		'/api/v[23]/vault/identity/:name',
		t.middleware.verify_view_action_session,
		checkIfVaultInitialisedMiddleware,
		getIdentitySecretByNameHandler
	);

	app.get(
		'/api/v[23]/vault/identity',
		t.middleware.verify_view_action_session,
		checkIfVaultInitialisedMiddleware,
		getAllIdentitiesFromVaultHandler
	);

	app.put(
		'/api/v[23]/vault/identity',
		t.middleware.verify_import_action_session,
		checkIfVaultInitialisedMiddleware,
		upsertIdentitiesToVaultHandler
	);

	app.get(
		'/ak/api/v[23]/vault/identity/:name',
		t.middleware.verify_view_action_ak,
		checkIfVaultInitialisedMiddleware,
		getIdentitySecretByNameHandler
	);

	app.get(
		'/ak/api/v[23]/vault/identity',
		t.middleware.verify_view_action_ak,
		checkIfVaultInitialisedMiddleware,
		getAllIdentitiesFromVaultHandler
	);

	app.put(
		'/ak/api/v[23]/vault/identity',
		t.middleware.verify_import_action_ak,
		checkIfVaultInitialisedMiddleware,
		upsertIdentitiesToVaultHandler
	);
	return app;
};
