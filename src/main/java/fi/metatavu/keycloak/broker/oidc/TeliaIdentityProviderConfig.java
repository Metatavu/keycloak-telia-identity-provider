package fi.metatavu.keycloak.broker.oidc;

import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.models.IdentityProviderModel;

import java.util.Optional;

/**
 * OIDC identity provider config for Telia Tunnistus
 */
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
   * Returns used environment (pre-production or production)
   *
   * @return environment
   */
  public TeliaIdentityEnvironment getEnvironment() {
    return Optional.ofNullable(getConfig().get("environment"))
      .map(TeliaIdentityEnvironment::valueOf)
      .orElse(TeliaIdentityEnvironment.PRE_PRODUCTION);
  }

  /**
   * Sets used environment (pre-production or production)
   *
   * @param environment environment
   */
  public void setEnvironment(TeliaIdentityEnvironment environment) {
    getConfig().put("environment", environment.name());
  }

  /**
   * Returns username origin
   *
   * @return username origin
   */
  public TeliaIdentityUsernameOrigin getUsernameOrigin() {
    return Optional.ofNullable(getConfig().get("usernameOrigin"))
      .map(TeliaIdentityUsernameOrigin::valueOf)
      .orElse(TeliaIdentityUsernameOrigin.SUBJECT);
  }

  /**
   * Sets username origin
   *
   * @param usernameOrigin username origin
   */
  public void setUsernameOrigin(final TeliaIdentityUsernameOrigin usernameOrigin) {
    getConfig().put("usernameOrigin", usernameOrigin.name());
  }

}