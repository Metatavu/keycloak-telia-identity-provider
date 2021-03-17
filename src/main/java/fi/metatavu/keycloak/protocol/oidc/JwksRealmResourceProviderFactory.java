package fi.metatavu.keycloak.protocol.oidc;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.services.resource.RealmResourceProvider;
import org.keycloak.services.resource.RealmResourceProviderFactory;

/**
 * SPI Factory class for providing jwksenc REST paths
 */
public class JwksRealmResourceProviderFactory implements RealmResourceProviderFactory {

  public static final String ID = "telia";

  @Override
  public String getId() {
    return ID;
  }

  @Override
  public int order() {
    return 0;
  }

  @Override
  public RealmResourceProvider create(KeycloakSession keycloakSession) {
    return new JwksRealmResourceProvider(keycloakSession);
  }

  @Override
  public void init(Config.Scope scope) {
  }

  @Override
  public void postInit(KeycloakSessionFactory keycloakSessionFactory) {
  }

  @Override
  public void close() {
  }
}