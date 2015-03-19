package org.gatsa.chapter2092.QRCrypt;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.eclipse.swt.layout.FillLayout;
import org.eclipse.swt.widgets.Display;
import org.eclipse.swt.widgets.Shell;

public class Main {
	
	public Main(Display display) {
		Shell shell = new Shell(display);
		shell.setText("Hello World");
		shell.setSize(250, 250);
		shell.setLayout(new FillLayout());
		shell.setToolTipText("Hello, world!");
		shell.open();
		while (!shell.isDisposed()) {
			if (!display.readAndDispatch()) {
				display.sleep();
			}
		}
	}

	public static void main(String[] args) {
		String plaintext = "Cryptography is pretty darn hard.";
		try {
			javax.crypto.KeyGenerator keygen;
			keygen = javax.crypto.KeyGenerator.getInstance("AES");
			keygen.init(128);
			javax.crypto.Cipher cipher;
			cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
			javax.crypto.SecretKey key = keygen.generateKey();
			cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key);
			System.out.println(plaintext);
			byte[] ciphertext;
			System.out.println(new String(ciphertext = cipher.doFinal(plaintext.getBytes()), "UTF8"));
			cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec(cipher.getIV()));
			System.out.println(new String(cipher.doFinal(ciphertext), "UTF8"));
			System.out.println("Plaintext length: " + plaintext.length());
			System.out.println("Ciphertext length: " + ciphertext.length);
			System.out.println("Key length: " + key.getEncoded().length);
			java.security.KeyPairGenerator keypairgen;
			keypairgen = java.security.KeyPairGenerator.getInstance("RSA");
			keypairgen.initialize(512);
			cipher = javax.crypto.Cipher.getInstance("RSA");
			java.security.KeyPair keypair = keypairgen.generateKeyPair();
			cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keypair.getPublic());
			System.out.println(plaintext);
			System.out.println(new String(ciphertext = cipher.doFinal(plaintext.getBytes()), "UTF8"));
			cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keypair.getPrivate());
			System.out.println(new String(cipher.doFinal(ciphertext), "UTF8"));
			System.out.println("Plaintext length: " + plaintext.length());
			System.out.println("Ciphertext length: " + ciphertext.length);
			System.out.println("Public key length: " + keypair.getPublic().getEncoded().length);
			System.out.println("Private key length: " + keypair.getPrivate().getEncoded().length);
			MessageDigest md = MessageDigest.getInstance("SHA-256");
			new QRCryptFile(key, new SecretKeySpec(Arrays.copyOf(md.digest(keypair.getPublic().getEncoded()), 16), "AES"), keypair.getPrivate(), keypair.getPublic(), new byte[] {}, new BufferedInputStream(new ByteArrayInputStream("QRCrypt FTW".getBytes())), new IvParameterSpec(new byte[] {})).writeFileTo(new BufferedOutputStream(new FileOutputStream(new File("C:\\Users\\Rishov\\Repositories\\finalbackendtest4.qrcrypt-file"))));
			System.out.println("Master key: " + bytesToHex(key.getEncoded()));
			System.out.println("AES key: " + bytesToHex(Arrays.copyOf(md.digest(keypair.getPublic().getEncoded()), 16)));
			//new QRCryptFileParser(new BufferedInputStream(new FileInputStream(new File("C:\\Users\\Rishov\\Repositories\\finalbackendtest4.qrcrypt-file"))), key.getEncoded()).toQRCryptFile().verify();
			new QRCryptFileParser(new BufferedInputStream(new FileInputStream(new File("C:\\Users\\Rishov\\Repositories\\finalbackendtest4.qrcrypt-file"))), key.getEncoded()).toQRCryptFile().verify();
			System.out.println(new String(new QRCryptFileParser(new BufferedInputStream(new FileInputStream(new File("C:\\Users\\Rishov\\Repositories\\finalbackendtest4.qrcrypt-file"))), key.getEncoded()).toQRCryptFile().getRawData()));
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		try {
			javax.crypto.Cipher cipher;
		} catch (Exception e) {
			e.printStackTrace();
		}
		//Display display = new Display();
		//new Main(display);
		//display.dispose();
	}
	
	final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
	    char[] hexChars = new char[bytes.length * 2];
	    for ( int j = 0; j < bytes.length; j++ ) {
	        int v = bytes[j] & 0xFF;
	        hexChars[j * 2] = hexArray[v >>> 4];
	        hexChars[j * 2 + 1] = hexArray[v & 0x0F];
	    }
	    return new String(hexChars);
	}

}
