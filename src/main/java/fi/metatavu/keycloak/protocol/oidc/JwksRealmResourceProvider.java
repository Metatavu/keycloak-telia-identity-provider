package fi.metatavu.keycloak.protocol.oidc;

import org.jboss.resteasy.annotations.cache.NoCache;
import org.jboss.resteasy.spi.HttpRequest;
import org.keycloak.crypto.KeyType;
import org.keycloak.crypto.KeyUse;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKBuilder;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.services.resource.RealmResourceProvider;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.Objects;

/**
 * Class for providing telia REST paths
 */
public class JwksRealmResourceProvider implements RealmResourceProvider {

	private KeycloakSession session;

	public JwksRealmResourceProvider(KeycloakSession session) {
		this.session = session;
	}

	@Override
	public Object getResource() {
		return this;
	}

	@GET
	@Path("/protocol/openid-connect/certs")
	@Produces(MediaType.APPLICATION_JSON)
	@NoCache
	public Response getCerts(@Context HttpRequest request) {
		KeycloakContext context = session.getContext();
		RealmModel realm = context.getRealm();

		JWK[] jwks = session.keys().getKeysStream(realm)
			.filter(k -> k.getStatus().isEnabled() && k.getPublicKey() != null)
			.map(k -> {
				JWKBuilder b = JWKBuilder.create().kid(k.getKid()).algorithm(k.getAlgorithm());
				if (k.getType().equals(KeyType.RSA)) {
					JWK rsa = b.rsa(k.getPublicKey(), k.getCertificate());
					if (k.getUse() == KeyUse.ENC) {
						rsa.setPublicKeyUse("enc");
					}

					return rsa;
				} else if (k.getType().equals(KeyType.EC)) {
					return b.ec(k.getPublicKey());
				}
				return null;
			})
			.filter(Objects::nonNull)
			.toArray(JWK[]::new);

		JSONWebKeySet keySet = new JSONWebKeySet();
		keySet.setKeys(jwks);

		return Response.ok(keySet).build();
	}

	@Override
	public void close() {
	}
}