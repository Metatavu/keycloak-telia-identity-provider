package fi.metatavu.keycloak.broker.oidc;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

/**
 * OIDC identity provider config for Telia Tunnistus
 */
public class TeliaIdentityProviderConfig extends OIDCIdentityProviderConfig {

  /**
   * Constructor
   *
   * @param model indentity provider model
   */
  public TeliaIdentityProviderConfig(IdentityProviderModel model) {
    super(model);
  }

  /**
   * Constructor
   */
  public TeliaIdentityProviderConfig() {

  }
}
