package fi.metatavu.keycloak.broker.oidc;

import org.keycloak.broker.oidc.OIDCIdentityProviderFactory;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;

/**
 * OIDC identity provider factory for Telia Tunnistus
 */
public class TeliaIdentityProviderFactory extends OIDCIdentityProviderFactory {

  public static final String PROVIDER_ID = "telia";

  @Override
  public String getName() {
    return "Telia Tunnistus";
  }

  @Override
  public TeliaIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
    return new TeliaIdentityProvider(session, new TeliaIdentityProviderConfig(model));
  }

  @Override
  public TeliaIdentityProviderConfig createConfig() {
    return new TeliaIdentityProviderConfig();
  }

  @Override
  public String getId() {
    return PROVIDER_ID;
  }
}
