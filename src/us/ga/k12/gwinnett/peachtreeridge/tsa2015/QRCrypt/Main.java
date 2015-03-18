package us.ga.k12.gwinnett.peachtreeridge.tsa2015.QRCrypt;

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
		javax.crypto.KeyGenerator keygen;
		try {
			keygen = javax.crypto.KeyGenerator.getInstance("AES");
			keygen.init(128);
			javax.crypto.Cipher cipher;
			cipher = javax.crypto.Cipher.getInstance("AES/CBC/PKCS5Padding");
			java.security.Key key = keygen.generateKey();
			cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec("1111111111111111".getBytes()));
			System.out.println(plaintext);
			byte[] ciphertext;
			System.out.println(new String(ciphertext = cipher.doFinal(plaintext.getBytes()), "UTF8"));
			cipher.init(javax.crypto.Cipher.DECRYPT_MODE, key, new javax.crypto.spec.IvParameterSpec("1111111111111111".getBytes()));
			System.out.println(new String(cipher.doFinal(ciphertext), "UTF8"));
			System.out.println("Plaintext length: " + plaintext.length());
			System.out.println("Ciphertext length: " + ciphertext.length);
			System.out.println("Key length: " + key.getEncoded().length);
		} catch (Exception e) {
			e.printStackTrace();
		}
		java.security.KeyPairGenerator keypairgen;
		try {
			keypairgen = java.security.KeyPairGenerator.getInstance("RSA");
			keypairgen.initialize(512);
			javax.crypto.Cipher cipher;
			cipher = javax.crypto.Cipher.getInstance("RSA");
			java.security.KeyPair keypair = keypairgen.generateKeyPair();
			cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, keypair.getPublic());
			System.out.println(plaintext);
			byte[] ciphertext;
			System.out.println(new String(ciphertext = cipher.doFinal(plaintext.getBytes()), "UTF8"));
			cipher.init(javax.crypto.Cipher.DECRYPT_MODE, keypair.getPrivate());
			System.out.println(new String(cipher.doFinal(ciphertext), "UTF8"));
			System.out.println("Plaintext length: " + plaintext.length());
			System.out.println("Ciphertext length: " + ciphertext.length);
			System.out.println("Public key length: " + keypair.getPublic().getEncoded().length);
			System.out.println("Private key length: " + keypair.getPrivate().getEncoded().length);
		} catch (Exception e) {
			e.printStackTrace();
		}
		Display display = new Display();
		new Main(display);
		display.dispose();
	}

}
