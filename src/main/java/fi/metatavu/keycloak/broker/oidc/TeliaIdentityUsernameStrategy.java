package fi.metatavu.keycloak.broker.oidc;

/**
 * Enum that specifies how username is resolved
 */
public enum TeliaIdentityUsernameStrategy {

	/**
	 * IDToken sub -field is used as username (default)
	 */
	SUBJECT,

	/**
	 * SSN is used as username
	 */
	SSN,

	/**
	 * Hashed (SHA-256) SSN is used as username
	 */
	HASHED_SSN

}
