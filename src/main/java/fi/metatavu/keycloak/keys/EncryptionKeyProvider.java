package fi.metatavu.keycloak.keys;

import org.keycloak.common.util.KeyUtils;
import org.keycloak.common.util.PemUtils;
import org.keycloak.component.ComponentModel;
import org.keycloak.crypto.*;
import org.keycloak.keys.Attributes;
import org.keycloak.keys.KeyProvider;
import org.keycloak.models.RealmModel;

import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.stream.Stream;

/**
 * Provider for Telia RSA encryption keys
 */
public class EncryptionKeyProvider implements KeyProvider {

  private final KeyStatus status;
  private final ComponentModel model;
  private final KeyWrapper key;
  private final String algorithm;

  /**
   * Constructor
   *
   * @param realm realm
   * @param model component model
   */
  public EncryptionKeyProvider(RealmModel realm, ComponentModel model) {
    this.model = model;
    this.status = KeyStatus.from(model.get(Attributes.ACTIVE_KEY, true), model.get(Attributes.ENABLED_KEY, true));
    this.algorithm = model.get(Attributes.ALGORITHM_KEY, Algorithm.RS256);

    if (model.hasNote(KeyWrapper.class.getName())) {
      key = model.getNote(KeyWrapper.class.getName());
    } else {
      key = loadKey(realm, model);
      model.setNote(KeyWrapper.class.getName(), key);
    }
  }

  @Override
  public Stream<KeyWrapper> getKeysStream() {
    return Stream.of(key);
  }

  /**
   * Loads a key
   *
   * @param realm realm
   * @param model component model
   * @return loaded key
   */
  private KeyWrapper loadKey(RealmModel realm, ComponentModel model) {
    String privateRsaKeyPem = model.getConfig().getFirst(Attributes.PRIVATE_KEY_KEY);
    String certificatePem = model.getConfig().getFirst(Attributes.CERTIFICATE_KEY);

    PrivateKey privateKey = PemUtils.decodePrivateKey(privateRsaKeyPem);
    PublicKey publicKey = KeyUtils.extractPublicKey(privateKey);

    KeyPair keyPair = new KeyPair(publicKey, privateKey);
    X509Certificate certificate = PemUtils.decodeCertificate(certificatePem);

    return createKeyWrapper(keyPair, certificate);
  }

  /**
   * Creates key wrapper
   *
   * @param keyPair     key pair
   * @param certificate certificate
   * @return key wrapper
   */
  private KeyWrapper createKeyWrapper(KeyPair keyPair, X509Certificate certificate) {
    KeyWrapper key = new KeyWrapper();

    key.setProviderId(model.getId());
    key.setProviderPriority(model.get("priority", 0L));

    key.setKid(KeyUtils.createKeyId(keyPair.getPublic()));
    key.setUse(KeyUse.ENC);
    key.setType(KeyType.RSA);
    key.setAlgorithm(algorithm);
    key.setStatus(status);
    key.setPrivateKey(keyPair.getPrivate());
    key.setPublicKey(keyPair.getPublic());
    key.setCertificate(certificate);

    return key;
  }
}
