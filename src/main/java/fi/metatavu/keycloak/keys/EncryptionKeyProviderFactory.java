package fi.metatavu.keycloak.keys;

import org.keycloak.common.util.CertificateUtils;
import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.component.ComponentValidationException;
import org.keycloak.keys.AbstractRsaKeyProviderFactory;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.keys.KeyProviderFactory;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.provider.ConfigurationValidationHelper;
import org.keycloak.provider.ProviderConfigProperty;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.util.List;

/**
 * SPI factory class for Telia encryption key providers
 */
public class EncryptionKeyProviderFactory extends AbstractRsaKeyProviderFactory implements KeyProviderFactory {

	public static final String ID = "telia-rsa-enc";
	private static final String HELP_TEXT = "RSA key provider for Telia encryption purposes";

	private static final List<ProviderConfigProperty> CONFIG_PROPERTIES = configurationBuilder()
		.property(Attributes.PRIVATE_KEY_PROPERTY)
		.property(Attributes.CERTIFICATE_PROPERTY)
		.build();

	@Override
	public KeyProvider create(KeycloakSession session, ComponentModel model) {
		return new EncryptionKeyProvider(session.getContext().getRealm(), model);
	}

	@Override
	public void validateConfiguration(KeycloakSession session, RealmModel realm, ComponentModel model) throws ComponentValidationException {
		ConfigurationValidationHelper.check(model)
			.checkLong(Attributes.PRIORITY_PROPERTY, false)
			.checkBoolean(Attributes.ENABLED_PROPERTY, false)
			.checkBoolean(Attributes.ACTIVE_PROPERTY, false);

		ConfigurationValidationHelper.check(model)
			.checkSingle(Attributes.PRIVATE_KEY_PROPERTY, true)
			.checkSingle(Attributes.CERTIFICATE_PROPERTY, false);

		KeyPair keyPair;
		try {
			PrivateKey privateKey = PemUtils.decodePrivateKey(model.get(Attributes.PRIVATE_KEY_KEY));
			PublicKey publicKey = KeyUtils.extractPublicKey(privateKey);
			keyPair = new KeyPair(publicKey, privateKey);
		} catch (Throwable t) {
			throw new ComponentValidationException("Failed to decode private key", t);
		}

		if (model.contains(Attributes.CERTIFICATE_KEY)) {
			Certificate certificate;
			try {
				certificate = PemUtils.decodeCertificate(model.get(Attributes.CERTIFICATE_KEY));
			} catch (Throwable t) {
				throw new ComponentValidationException("Failed to decode certificate", t);
			}

			if (certificate == null) {
				throw new ComponentValidationException("Failed to decode certificate");
			}

			if (!certificate.getPublicKey().equals(keyPair.getPublic())) {
				throw new ComponentValidationException("Certificate does not match private key");
			}
		} else {
			try {
				Certificate certificate = CertificateUtils.generateV1SelfSignedCertificate(keyPair, realm.getName());
				model.put(Attributes.CERTIFICATE_KEY, PemUtils.encodeCertificate(certificate));
			} catch (Throwable t) {
				throw new ComponentValidationException("Failed to generate self-signed certificate");
			}
		}
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return CONFIG_PROPERTIES;
	}

	@Override
	public String getHelpText() {
		return HELP_TEXT;
	}

	@Override
	public String getId() {
		return ID;
	}

}
