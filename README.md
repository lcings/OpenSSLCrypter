# OpenSSLCrypter
Android AES Crypter With Salt

安卓实现AES加盐的Crypter

无缝对接AES加密解密:
http://tool.chinaz.com/Tools/textencrypt.aspx
http://tool.oschina.net/encrypt
https://www.sojson.com/encrypt_aes.html
http://encode.chahuo.com/

Sample:
    String passwd = "123456";
    String str = "Hello,OpenSSLCrypter!";
    String enco = "U2FsdGVkX1/QIsEdaQjeI8urDkQ+J8haqoODH1P5ouxr3A0/FVehqydZXaDVtOOn";

    //加密1
    String s1 = OpenSSLCrypter.EncryptAES(str, passwd);
    Log.e("OpenSSLCrypter", "EncryptAES(String encryptStr, String password):" + s1);

    //加密2
    byte[] salt = new byte[8];
    new Random().nextBytes(salt);
    String s2 = OpenSSLCrypter.EncryptAESWithSalt(str, passwd, salt);
    Log.e("OpenSSLCrypter", "EncryptAESWithSalt(String encryptStr, String password, byte[] salt) :" + s2);

    //加密3
    byte[] b1 = OpenSSLCrypter.EncryptAESWithSalt(str.getBytes(), passwd, salt);
    String b1Str = new String(Base64.encode(b1, Base64.DEFAULT));
    Log.e("OpenSSLCrypter", "EncryptAESWithSalt(byte[] encryptData, String password, byte[] salt):" + b1Str);

    //解密1
    String s3 = OpenSSLCrypter.DecryptAES(enco, passwd);	
    Log.e("OpenSSLCrypter", "DecryptAES(String decryptStr, String password) :" + s3);

    //解密2
    byte[] b2 = OpenSSLCrypter.DecryptAES(Base64.decode(enco, Base64.DEFAULT), passwd);	
    String b2Str = new String(b2);
    Log.e("OpenSSLCrypter", "DecryptAES(byte[] encryptData, String password):" + b2Str);
