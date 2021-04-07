package fi.metatavu.keycloak.broker.oidc;

/**
 * Enum that specifies how identity is resolved
 */
public enum TeliaIdentityStrategy {

	/**
	 * IDToken sub -field is used as username (default)
	 */
	SUBJECT,

	/**
	 * Hashed (SHA-256) SSN is used as username
	 */
	HASHED_SSN

}
