package demo;

import org.jrichardsz.crypt.easycryptex.Cryptex;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CryptexRsaDemo {

  private static Logger logger = LoggerFactory.getLogger(CryptexRsaDemo.class);

  public static void main(String[] args) throws Exception {
    Cryptex crypter = new Cryptex();

    String cryptedData = System.getenv("CRYPTED_TEXT");
    String plainText =
        crypter.decryptData(cryptedData, System.getenv("PRIVATE_KEY_FILE_PATH"), "RSA", "UTF-8");
    logger.info("Plain text:" + plainText);

  }
}
