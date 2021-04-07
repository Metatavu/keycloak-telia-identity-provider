package fi.metatavu.keycloak.broker.oidc;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import java.util.Optional;

/**
 * OIDC identity provider config for Telia Tunnistus
 */
@SuppressWarnings("unused")
public class TeliaIdentityProviderConfig extends OIDCIdentityProviderConfig {

  /**
   * Constructor
   *
   * @param model identity provider model
   */
  public TeliaIdentityProviderConfig(IdentityProviderModel model) {
    super(model);
  }

  /**
   * Constructor
   */
  public TeliaIdentityProviderConfig() {
  }

  /**
   * Returns identity strategy
   *
   * @return identity strategy
   */
  public TeliaIdentityStrategy getIdentityStrategy() {
    return Optional.ofNullable(getConfig().get("identityStrategy"))
      .map(TeliaIdentityStrategy::valueOf)
      .orElse(TeliaIdentityStrategy.SUBJECT);
  }

  /**
   * Sets identity strategy
   *
   * @param IdentityStrategy identity strategy
   */
  public void setIdentityStrategy(final TeliaIdentityStrategy IdentityStrategy) {
    getConfig().put("identityStrategy", IdentityStrategy.name());
  }

  /**
   * Returns username strategy
   *
   * @return username strategy
   */
  public TeliaIdentityUsernameStrategy getUsernameStrategy() {
    return Optional.ofNullable(getConfig().get("usernameStrategy"))
      .map(TeliaIdentityUsernameStrategy::valueOf)
      .orElse(TeliaIdentityUsernameStrategy.SUBJECT);
  }

  /**
   * Sets username strategy
   *
   * @param usernameStrategy username strategy
   */
  public void setUsernameStrategy(final TeliaIdentityUsernameStrategy usernameStrategy) {
    getConfig().put("usernameStrategy", usernameStrategy.name());
  }

}