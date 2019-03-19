package com.lcings.android.util;

/*
 * @class name  [OpenSSLCrypter]
 * @function    [EncryptAES/EncryptAESWithSalt/DecryptAES]
 * @version     [1.0.0/2019-03-20]
 */

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import android.util.Base64;
import java.nio.charset.Charset;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Random;

public final class OpenSSLCrypter {
    private static final String SALTED_STRING = "Salted__";
    private static final String MSG_DIGEST = "MD5";
    private static final String CIPHER_NAME = "AES";
    private static final String CIPHER_INSTANCE = "AES/CBC/PKCS5Padding";

    public static byte[] DecryptAES(byte[] encryptData, String password) {
    	final byte[] salt = Arrays.copyOfRange(encryptData, SALTED_STRING.getBytes().length, SALTED_STRING.getBytes().length + 8);
        Cipher cipher = initCrypter(password, salt, Cipher.DECRYPT_MODE);
        byte[] clear = null;
		try {
			clear = cipher.doFinal(encryptData, 16, encryptData.length - 16);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return clear;
    }
    
    public static String DecryptAES(String decryptStr, String password) {
        final byte[] encryptData = Base64.decode(decryptStr, Base64.DEFAULT);
        byte[] out = DecryptAES(encryptData, password);
        return new String(out).replaceAll("\n", "");
    }

    public static byte[] EncryptAESWithSalt(byte[] encryptData, String password, byte[] salt)
    {
    	Cipher cipher = initCrypter(password, salt, Cipher.ENCRYPT_MODE); 
        try {
        	encryptData = cipher.doFinal(encryptData);
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return encryptData;
    }
    
    public static byte[] EncryptAESWithSalt(byte[] encryptData, String password)
    {
        byte[] salt = new byte[8];
        new Random().nextBytes(salt);
        return EncryptAESWithSalt(encryptData, password, salt);
    }
    
    public static String EncryptAESWithSalt(String encryptStr, String password, byte[] salt) {
    	byte[] bytes = EncryptAESWithSalt(encryptStr.getBytes(Charset.forName("UTF-8")), password, salt);
        byte[] result = new byte[bytes.length + 16];
        System.arraycopy(SALTED_STRING.getBytes(), 0, result, 0, 8);
        System.arraycopy(salt, 0, result, 8, 8);
        System.arraycopy(bytes, 0, result, 16, bytes.length);
        bytes = Base64.encode(result, Base64.DEFAULT);
        return new String(bytes);
    }
    
    public static String EncryptAES(String encryptStr, String password) {
        byte[] salt = new byte[8];
        new Random().nextBytes(salt);
        String result = "";
        try {
        	result = EncryptAESWithSalt(encryptStr, password,  salt);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return result;
    }
    
    private static byte[] addArrays(final byte[] arr1, final byte[] arr2) {
        final byte[] resArr = new byte[arr1.length + arr2.length];
        System.arraycopy(arr1, 0, resArr, 0, arr1.length);
        System.arraycopy(arr2, 0, resArr, arr1.length, arr2.length);
        return resArr;
    }
    
    private static Cipher initCrypter(String password, byte[] salt, int mode) {
        final byte[] pass = password.getBytes();
        final byte[] passAndSalt = addArrays(pass, salt);

        byte[] hash = new byte[0];
        byte[] keyAndIv = new byte[0];
        for (int i = 0; i < 3 && keyAndIv.length < 48; i++) {
            final byte[] hashData = addArrays(hash, passAndSalt);
            MessageDigest md = null;
			try {
				md = MessageDigest.getInstance(MSG_DIGEST);
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
            hash = md.digest(hashData);
            keyAndIv = addArrays(keyAndIv, hash);
        }

        final byte[] keyValue = Arrays.copyOfRange(keyAndIv, 0, 32);
        final SecretKeySpec key = new SecretKeySpec(keyValue, CIPHER_NAME);
        final byte[] iv = Arrays.copyOfRange(keyAndIv, 32, 48);
        Cipher cipher = null;
		try {
			cipher = Cipher.getInstance(CIPHER_INSTANCE);
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}   
        try {
			cipher.init(mode, key, new IvParameterSpec(iv));
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
        return cipher;
    }
}