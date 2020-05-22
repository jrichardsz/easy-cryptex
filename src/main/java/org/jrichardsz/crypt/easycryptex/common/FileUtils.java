package org.jrichardsz.crypt.easycryptex.common;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FileUtils {

  public static boolean isBase64Encode(String string) {
    String pattern = "^([A-Za-z0-9+/]{4})*([A-Za-z0-9+/]{4}|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{2}==)$";
    Pattern r = Pattern.compile(pattern);
    Matcher m = r.matcher(string);
    return m.find();
  }

}
