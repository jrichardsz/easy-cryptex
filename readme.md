# Decryption Usage

Export required values or use directly

```sh
export CRYPTED_TEXT="mFtLhmW***k8BuvA=="
export PRIVATE_KEY_FILE_PATH="/tmp/private_key.pem"
```


```java
Cryptex crypter = new Cryptex();
String cryptedData = System.getenv("CRYPTED_TEXT");
String plainText = crypter.decryptData(cryptedData, System.getenv("PRIVATE_KEY_FILE_PATH"), "RSA", "UTF-8");
System.out.println("Plain text:" + plainText);
```
