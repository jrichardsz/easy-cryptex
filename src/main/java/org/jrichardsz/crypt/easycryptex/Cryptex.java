package org.jrichardsz.crypt.easycryptex;

import java.lang.reflect.Method;
import java.nio.charset.Charset;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.Cipher;
import org.jrichardsz.crypt.easycryptex.common.FileUtils;
import org.jrichardsz.crypt.easycryptex.common.KeyFileUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Cryptex {

  private Logger logger = LoggerFactory.getLogger(this.getClass());

  public String decryptData(String data, String privateKeyFilePath,
      String cryptographicAlgorithmToUseInDecryption, String outputDecryptionCharset)
      throws Exception {
    String decryptionMethodByFileType = detectDecryptionMethodByFileType(data);
    return (String) executeSpecificDecryption(decryptionMethodByFileType, data, privateKeyFilePath,
        cryptographicAlgorithmToUseInDecryption, outputDecryptionCharset, this);
  }

  private String detectDecryptionMethodByFileType(String data) throws Exception {
    if (FileUtils.isBase64Encode(data)) {
      return "decryptBase64Data";
    }

    throw new Exception(
        "Crypted text to decrypt is not base64. Maybe is binary!. Decryption is not support");
  }

  private Object executeSpecificDecryption(String methodName, Object argumentInstance1,
      Object argumentInstance2, Object argumentInstance3, Object argumentInstance4,
      Cryptex cryptexPersistence) throws Exception {

    Method method = null;

    try {
      method = cryptexPersistence.getClass().getMethod(methodName, argumentInstance1.getClass(),
          argumentInstance2.getClass(), argumentInstance3.getClass(), argumentInstance4.getClass());
    } catch (Exception e) {
      throw new Exception(
          "Error when method was being obtained from " + cryptexPersistence.getClass(), e);
    }

    Object response = null;
    try {
      response = method.invoke(cryptexPersistence, argumentInstance1, argumentInstance2,
          argumentInstance3, argumentInstance4);
      return response;
    } catch (Exception e) {
      throw new Exception(
          "Error when method was being executed in " + cryptexPersistence.getClass(), e);
    }

  }

  public String decryptBase64Data(String data, String privateKeyFilePath,
      String cryptographicAlgorithmToUseInDecryption, String outputDecryptionCharset)
      throws Exception {
    logger.info("----------------DECRYPTION STARTED------------");
    byte[] decryptedData = null;

    KeyFileUtils keyFileUtils = new KeyFileUtils();

    try {
      PrivateKey privateKey = keyFileUtils.loadKey(privateKeyFilePath);
      Cipher cipher = Cipher.getInstance(cryptographicAlgorithmToUseInDecryption);
      cipher.init(Cipher.DECRYPT_MODE, privateKey);
      byte[] bts = Base64.getMimeDecoder().decode(data);
      decryptedData = cipher.doFinal(bts);
      logger.info("----------------DECRYPTION COMPLETED------------");
      return new String(decryptedData, Charset.forName(outputDecryptionCharset));
    } catch (Exception e) {
      throw new Exception("Failed when decryption process was being performed.", e);
    }
  }

  public String encryptData(String data, String publicKeyFilePath,
      String cryptographicAlgorithmForPublicKey, String cryptographicAlgorithmToUseInEncryption,
      String outputeEncryptionCharset) throws Exception {
    logger.info("----------------ENCRYPTION STARTED------------");

    KeyFileUtils keyFileUtils = new KeyFileUtils();

    logger.info("Data Before Encryption :" + data);
    byte[] dataToEncrypt = data.getBytes();
    byte[] encryptedData = null;
    try {
      PublicKey pubKey =
          keyFileUtils.readPublicKeyFromFile(publicKeyFilePath, cryptographicAlgorithmForPublicKey);
      Cipher cipher = Cipher.getInstance(cryptographicAlgorithmToUseInEncryption);
      cipher.init(Cipher.ENCRYPT_MODE, pubKey);
      encryptedData = cipher.doFinal(dataToEncrypt);
      logger.debug("Encryted Data: " + encryptedData);

      logger.info("----------------ENCRYPTION COMPLETED------------");
      return new String(encryptedData, Charset.forName(outputeEncryptionCharset));

    } catch (Exception e) {
      throw new Exception("Failed when encryption process was being performed.", e);
    }

  }
}
