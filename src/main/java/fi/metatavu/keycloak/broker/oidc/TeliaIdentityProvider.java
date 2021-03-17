package fi.metatavu.keycloak.broker.oidc;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jwt.EncryptedJWT;
import org.keycloak.broker.oidc.OIDCIdentityProvider;
import org.keycloak.broker.oidc.OIDCIdentityProviderConfig;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSInput;
import org.keycloak.jose.jws.crypto.RSAProvider;
import org.keycloak.keys.PublicKeyStorageProvider;
import org.keycloak.keys.loader.PublicKeyStorageManager;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.representations.IDToken;
import org.keycloak.representations.JsonWebToken;

import java.io.IOException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.text.ParseException;
import java.util.Arrays;

/**
 * OIDC identity provider for Telia Tunnistus
 */
public class TeliaIdentityProvider extends OIDCIdentityProvider {

    private static final String TOKEN_ATTRIBUTE_SEX = "urn:oid:1.2.246.575.1.15";
    private static final String TOKEN_ATTRIBUTE_BIRTHDAY = "urn:oid:1.3.6.1.5.5.7.9.1";
    private static final String TOKEN_ATTRIBUTE_SSN = "urn:oid:1.2.246.21";
    private static final String TOKEN_ATTRIBUTE_SATU = "urn:oid:1.2.246.22";
    private static final String TOKEN_ATTRIBUTE_NAME = "urn:oid:2.16.840.1.113730.3.1.241";
    private static final String TOKEN_ATTRIBUTE_GIVEN_NAME = "urn:oid:1.2.246.575.1.14";
    private static final String TOKEN_ATTRIBUTE_FAMILY_NAME = "urn:oid:2.5.4.4";

    /**
     * Constructor
     *
     * @param session Keycloak session
     * @param config provider config
     */
    public TeliaIdentityProvider(KeycloakSession session, OIDCIdentityProviderConfig config) {
        super(session, config);
    }

    @Override
    protected boolean verify(JWSInput jws) {
        PublicKey publicKey = getVerifyKey(jws);
        return publicKey != null && RSAProvider.verify(jws, publicKey);
    }

    /**
     * Resolves public key used for verifying the token
     *
     * @param jws JWS input
     * @return loaded key or null if loading has failed
     */
    private PublicKey getVerifyKey(JWSInput jws) {
        PublicKeyStorageProvider keyStorage = session.getProvider(PublicKeyStorageProvider.class);
        try {
            return PublicKeyStorageManager.getIdentityProviderPublicKey(session, session.getContext().getRealm(), getConfig(), jws);
        } catch (Exception e) {
            e.printStackTrace();
        }

        return loadVerifyKey(jws);
    }

    @Override
    protected JsonWebToken validateToken(String encodedToken, boolean ignoreAudience) {
        try {
            return super.validateToken(getDecryptedIdToken(encodedToken), ignoreAudience);
        } catch (ParseException e) {
            logger.error("Error occurred while parsing token", e);
        } catch (JOSEException e) {
            logger.error("Error occurred while decrypting token", e);
        }

        return null;
    }

    /**
     * Loads public key from Telia's JWKS URI.
     *
     * Telia's servers do not include "use" -field and Keycloak does not currently support
     * keys that are not specified for either sig or enc use.
     *
     * @param jws JWS input
     * @return loaded key or null if loading has failed
     */
    private PublicKey loadVerifyKey(JWSInput jws) {
        try {
            JSONWebKeySet jwks = JWKSHttpUtils.sendJwksRequest(session, getConfig().getJwksUrl());
            String kid = jws.getHeader().getKeyId();
            JWK jwk = Arrays.stream(jwks.getKeys())
              .filter(key -> key.getKeyId().equals(kid))
              .findFirst()
              .orElse(null);

            if (jwk == null) {
                return null;
            }

            JWKParser parser = JWKParser.create(jwk);
            KeyWrapper keyWrapper = new KeyWrapper();
            keyWrapper.setKid(jwk.getKeyId());

            if (jwk.getAlgorithm() != null) {
                keyWrapper.setAlgorithm(jwk.getAlgorithm());
            } else if (jwk.getKeyType().equalsIgnoreCase("RSA")) {
                keyWrapper.setAlgorithm("RS256");
            }

            keyWrapper.setType(jwk.getKeyType());
            keyWrapper.setUse(KeyUse.SIG);
            keyWrapper.setPublicKey(parser.toPublicKey());

            return (PublicKey) keyWrapper.getPublicKey();
        } catch (Exception e) {
            e.printStackTrace();
        }

        return null;
    }

    @Override
    protected BrokeredIdentityContext extractIdentity(AccessTokenResponse tokenResponse, String accessToken, JsonWebToken idToken) {
        String id = idToken.getSubject();
        BrokeredIdentityContext identity = new BrokeredIdentityContext(id);

        String name = (String) idToken.getOtherClaims().get(TOKEN_ATTRIBUTE_NAME);
        String givenName = (String)idToken.getOtherClaims().get(TOKEN_ATTRIBUTE_GIVEN_NAME);
        String familyName = (String)idToken.getOtherClaims().get(TOKEN_ATTRIBUTE_FAMILY_NAME);
        String email = (String) idToken.getOtherClaims().get(IDToken.EMAIL);
        String sex = (String) idToken.getOtherClaims().get(TOKEN_ATTRIBUTE_SEX);
        String birthday = (String) idToken.getOtherClaims().get(TOKEN_ATTRIBUTE_BIRTHDAY);
        String ssn = (String) idToken.getOtherClaims().get(TOKEN_ATTRIBUTE_SSN);
        String satu = (String) idToken.getOtherClaims().get(TOKEN_ATTRIBUTE_SATU);

        identity.getContextData().put(VALIDATED_ID_TOKEN, idToken);
        identity.setId(id);

        if (givenName != null) {
            identity.setFirstName(givenName);
        }

        if (familyName != null) {
            identity.setLastName(familyName);
        }

        if (givenName == null && familyName == null) {
            identity.setName(name);
        }

        identity.setEmail(email);
        identity.setBrokerUserId(getConfig().getAlias() + "." + id);
        identity.setUsername(id);

        if (ssn != null) {
            identity.setUserAttribute("SSN", ssn);
        }

        if (satu != null) {
            identity.setUserAttribute("SATU", satu);
        }

        if (sex != null) {
            identity.setUserAttribute("SEX", sex);
        }

        if (birthday != null) {
            identity.setUserAttribute("BIRTHDAY", birthday);
        }

        if (tokenResponse != null && tokenResponse.getSessionState() != null) {
            identity.setBrokerSessionId(getConfig().getAlias() + "." + tokenResponse.getSessionState());
        }

        if (tokenResponse != null) identity.getContextData().put(FEDERATED_ACCESS_TOKEN_RESPONSE, tokenResponse);
        if (tokenResponse != null) processAccessTokenResponse(identity, tokenResponse);

        return identity;
    }

    /**
     * Decrypts ID Token using encryption key specified for the domain
     *
     * @param encryptedToken encrypted token
     * @return decrypted token
     * @throws ParseException thrown when token parsing fails
     * @throws JOSEException thrown when error occurs when decrypting the token
     */
    private String getDecryptedIdToken(String encryptedToken) throws ParseException, JOSEException {
        KeycloakContext context = session.getContext();
        RealmModel realm = context.getRealm();
        KeyManager keyManager = session.keys();
        EncryptedJWT jwt = EncryptedJWT.parse(encryptedToken);
        String kid = jwt.getHeader().getKeyID();
        KeyWrapper activeKey = keyManager.getKey(realm, kid, KeyUse.ENC, "RS256");
        Key privateKey = activeKey.getPrivateKey();
        RSADecrypter decrypter = new RSADecrypter((PrivateKey) privateKey);
        jwt.decrypt(decrypter);
        return jwt.getPayload().toString();
    }

}
