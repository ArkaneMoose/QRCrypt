package us.ga.k12.gwinnett.peachtreeridge.tsa2015.QRCrypt;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

public class QRCryptFile {

	private static final byte[] MAGIC_NUMBER = "QRCr".getBytes();
	private static final int VERSION_NUMBER = 0; 
	
	private static final int STREAM_BLOCK_SIZE = 2048;
	
	private SecretKey masterKey;
	private SecretKey aesKey;
	private PrivateKey privateKey;
	private PublicKey publicKey;
	private byte[] signature;
	private BufferedInputStream inputStream;
	private boolean readOnly;
	
	public class InvalidQRCryptException extends Exception {
		private static final long serialVersionUID = -7668390109686437471L;
		
	}
	
	public QRCryptFile(SecretKey aesKey, PublicKey publicKey, byte[] signature, DigestInputStream dis) {
		this.aesKey = aesKey;
		this.publicKey = publicKey;
		this.signature = signature;
		this.readOnly = true;
	}
	
	public QRCryptFile(SecretKey masterKey, SecretKey aesKey, PrivateKey privateKey, PublicKey publicKey, byte[] signature, BufferedInputStream is) {
		this.masterKey = masterKey;
		this.aesKey = aesKey;
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.signature = signature;
		this.inputStream = is;
		this.readOnly = false;
	}
	
	public void verify() throws InvalidQRCryptException, NoSuchAlgorithmException, Exception {
		Cipher cipher;
		MessageDigest md;
		byte[] byteArray;
		
		md = MessageDigest.getInstance("SHA-256");
		if (md.digest(publicKey.getEncoded()) != aesKey.getEncoded()) throw new InvalidQRCryptException();
		cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		byteArray = new byte[STREAM_BLOCK_SIZE];
		md.reset();
		inputStream.read(byteArray);
		inputStream.reset();
		//while ((dis.)) {
			
		//}
		//if (!Arrays.equals(cipher.doFinal(signature), )) throw new InvalidQRCryptException();
	}
	
	public void writeFileTo(BufferedOutputStream outputStream) throws IOException {
		outputStream.write(MAGIC_NUMBER);
		outputStream.write(VERSION_NUMBER);
		//outputStream.write
	}

}
