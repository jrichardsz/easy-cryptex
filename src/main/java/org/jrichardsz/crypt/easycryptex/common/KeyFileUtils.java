package org.jrichardsz.crypt.easycryptex.common;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class KeyFileUtils {

  private Logger logger = LoggerFactory.getLogger(this.getClass());

  private static final String PKCS_1_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
  private static final String PKCS_1_PEM_FOOTER = "-----END RSA PRIVATE KEY-----";
  private static final String PKCS_8_PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
  private static final String PKCS_8_PEM_FOOTER = "-----END PRIVATE KEY-----";

  public PrivateKey loadKey(String keyFilePath) throws GeneralSecurityException, IOException {
    byte[] keyDataBytes = Files.readAllBytes(Paths.get(keyFilePath));
    String keyDataString = new String(keyDataBytes, StandardCharsets.UTF_8);

    if (keyDataString.contains(PKCS_1_PEM_HEADER)) {
      logger.info("private key file is PKCS_1");
      // OpenSSL / PKCS#1 Base64 PEM encoded file
      keyDataString = keyDataString.replace(PKCS_1_PEM_HEADER, "");
      keyDataString = keyDataString.replace(PKCS_1_PEM_FOOTER, "");
      return readPkcs1PrivateKey(Base64.getMimeDecoder().decode(keyDataString));
    }

    if (keyDataString.contains(PKCS_8_PEM_HEADER)) {
      // PKCS#8 Base64 PEM encoded file
      logger.info("PKCS_8");
      keyDataString = keyDataString.replace(PKCS_8_PEM_HEADER, "");
      keyDataString = keyDataString.replace(PKCS_8_PEM_FOOTER, "");
      return readPkcs8PrivateKey(Base64.getDecoder().decode(keyDataString));
    }

    logger.info("PKCS#8 DER");
    // We assume it's a PKCS#8 DER encoded binary file
    return readPkcs8PrivateKey(Files.readAllBytes(Paths.get(keyFilePath)));
  }

  public PublicKey readPublicKeyFromFile(String fileName, String cryptographicAlgorithm)
      throws Exception {
    FileInputStream fis = null;
    ObjectInputStream ois = null;
    try {
      fis = new FileInputStream(new File(fileName));
      ois = new ObjectInputStream(fis);

      BigInteger modulus = (BigInteger) ois.readObject();
      BigInteger exponent = (BigInteger) ois.readObject();

      // Get Public Key
      RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
      KeyFactory fact = KeyFactory.getInstance(cryptographicAlgorithm);
      PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);

      return publicKey;

    } catch (Exception e) {
      throw new Exception(
          String.format("Failed when public key file: %s was being readed as %s using %s", fileName,
              PublicKey.class, cryptographicAlgorithm));
    } finally {
      if (ois != null) {
        ois.close();
        if (fis != null) {
          fis.close();
        }
      }
    }
  }

  private PrivateKey readPkcs8PrivateKey(byte[] pkcs8Bytes) throws GeneralSecurityException {
    KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
    PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(pkcs8Bytes);
    try {
      return keyFactory.generatePrivate(keySpec);
    } catch (InvalidKeySpecException e) {
      throw new IllegalArgumentException("Unexpected key format!", e);
    }
  }

  private PrivateKey readPkcs1PrivateKey(byte[] pkcs1Bytes) throws GeneralSecurityException {
    // We can't use Java internal APIs to parse ASN.1 structures, so we build a PKCS#8 key Java can
    // understand
    int pkcs1Length = pkcs1Bytes.length;
    int totalLength = pkcs1Length + 22;
    byte[] pkcs8Header = new byte[] {0x30, (byte) 0x82, (byte) ((totalLength >> 8) & 0xff),
        (byte) (totalLength & 0xff), // Sequence + total length
        0x2, 0x1, 0x0, // Integer (0)
        0x30, 0xD, 0x6, 0x9, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0xD, 0x1, 0x1, 0x1,
        0x5, 0x0, // Sequence: 1.2.840.113549.1.1.1, NULL
        0x4, (byte) 0x82, (byte) ((pkcs1Length >> 8) & 0xff), (byte) (pkcs1Length & 0xff) // Octet
                                                                                          // string
                                                                                          // +
                                                                                          // length
    };
    byte[] pkcs8bytes = join(pkcs8Header, pkcs1Bytes);
    return readPkcs8PrivateKey(pkcs8bytes);
  }

  private byte[] join(byte[] byteArray1, byte[] byteArray2) {
    byte[] bytes = new byte[byteArray1.length + byteArray2.length];
    System.arraycopy(byteArray1, 0, bytes, 0, byteArray1.length);
    System.arraycopy(byteArray2, 0, bytes, byteArray1.length, byteArray2.length);
    return bytes;
  }


}
