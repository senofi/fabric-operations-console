const nodeVault = require('node-vault');

module.exports = function (logger, ev, t) {
	const app = t.express.Router();

	let vaultData = {};
	try {
		vaultData = require('/server/conf/vault/vault-config.json');
	} catch (error) {
		logger.error('Error while loading Vault configuration file! Error: ', error);
	}

	const {
		url: VAULT_URL,
		apiVersion: VAULT_API_VERSION,
		username: VAULT_USERNAME,
		password: VAULT_PASSWORD,
		orgName: VAULT_ORG_NAME,
		vaultPath: VAULT_PATH
	} = vaultData;

	const vaultIdentitiesPath = `${VAULT_ORG_NAME}/data/${VAULT_PATH}`;
	const vaultFolderContentPath = `${VAULT_ORG_NAME}/metadata/${VAULT_PATH}`;

	// Vault initialisation
	let vault;
	let isVaultInitialised = false;

	const initVaultClient = async () => {
		const options = {
			apiVersion: VAULT_API_VERSION,
			endpoint: VAULT_URL
		};

		try {
			vault = nodeVault(options);
			await vault.userpassLogin({
				username: VAULT_USERNAME,
				password: VAULT_PASSWORD
			});
			isVaultInitialised = true;
		} catch (error) {
			const msg = 'Error while establishing connection to Vault!';
			logger.error(`${msg} Error: ${error}`);
		}
	};

	initVaultClient();

	// Check if Vault client initialised middleware
	const checkIfVaultInitialisedMiddleware = (req, res, next) => {
		if (isVaultInitialised) {
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

	// Definition of requests handling functions
	const getIdentitySecretByNameHandler = async (req, res) => {
		const name = req.params.name;
		let secret;
		try {
			secret = await vault
				.read(`${vaultIdentitiesPath}/` + name)
				.then((response) => response.data.data);
		} catch (error) {
			const msg = `Error while fetching identity with key ${name} from Vault!`;
			logger.error(`${msg} Error: ${error}`);
			res.status(t.ot_misc.get_code(error)).json({
				msg,
				reason: error
			});
			return;
		}

		const { data, id, peers, orderer, cas, tls_cas } = secret;
		const credentialsData = JSON.parse(data);

		const { credentials, msp_id } = credentialsData;
		const { certificate, private_key } = credentials;

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
		res.json(identity);
	};

	const getAllIdentitiesFromVaultHandler = async (req, res) => {
		let secretsNames = [];

		try {
			secretsNames = await vault
				.read(`${vaultFolderContentPath}?list=true`)
				.then((response) => response.data.keys);
		} catch (error) {
			const msg = 'Error while fetching identities\' secrets names from Vault!';
			logger.error(`${msg} Error: ${error}`);
			res.status(t.ot_misc.get_code(error)).json({
				msg,
				reason: error
			});
			return;
		}

		secretsNames = secretsNames.filter((e) => e[e.length - 1] !== '/');

		const secrets = {};
		try {
			for (const secretName of secretsNames) {
				const secret = await vault
					.read(`${vaultIdentitiesPath}/${secretName}`)
					.then((response) => response.data.data);
				const { data, id, peers, orderer, cas, tls_cas } = secret;
				const identity = JSON.parse(data);

				const { credentials, msp_id } = identity;
				const { certificate, private_key } = credentials;

				const certBuffer = Buffer.from(certificate);
				const privateKeyBuffer = Buffer.from(private_key);

				secrets[id] = {
					cert: certBuffer.toString('base64'),
					private_key: privateKeyBuffer.toString('base64'),
					msp_id,
					peers: JSON.parse(peers),
					orderer: JSON.parse(orderer),
					cas: JSON.parse(cas),
					tls_cas: JSON.parse(tls_cas)
				};
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
			const {
				cert,
				private_key,
				peers = [],
				orderer = [],
				cas = [],
				tls_cas = []
			} = identityValue;

			const componentsIds = [...peers, ...orderer, ...cas, ...tls_cas];

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
			let msp_id =
        Object.entries(mspIdsMap).length === 0
        	? ''
        	: Object.entries(mspIdsMap)[0];
			for (const key in mspIdsMap) {
				msp_id = mspIdsMap[key];
				break;
			}

			const bufferCert = Buffer.from(cert, 'base64');
			const bufferPrivateKey = Buffer.from(private_key, 'base64');
			const data = {
				credentials: {
					certificate: bufferCert.toString('utf-8'),
					private_key: bufferPrivateKey.toString('utf-8')
				},
				msp_id,
				type: 'X.509'
			};
			const secretIdentity = {
				data: JSON.stringify(data),
				id: key,
				peers: JSON.stringify(peers),
				orderer: JSON.stringify(orderer),
				cas: JSON.stringify(cas),
				tls_cas: JSON.stringify(tls_cas)
			};

			await vault
				.write(`${vaultIdentitiesPath}/${key}`, { data: secretIdentity }, {})
				.catch((e) => {
					errors.push(key);
				});
		}

		res.status(200).json({ errors });
	};

	// Routes definition

	app.get(
		'/api/v[23]/vault/identity/:name',
		t.middleware.verify_view_action_ak,
		checkIfVaultInitialisedMiddleware,
		getIdentitySecretByNameHandler
	);

	app.get(
		'/api/v[23]/vault/identity',
		t.middleware.verify_view_action_ak,
		checkIfVaultInitialisedMiddleware,
		getAllIdentitiesFromVaultHandler
	);

	app.put(
		'/api/v[23]/vault/identity',
		t.middleware.verify_view_action_ak,
		checkIfVaultInitialisedMiddleware,
		upsertIdentitiesToVaultHandler
	);

	return app;
};
