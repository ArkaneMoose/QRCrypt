package org.gatsa.chapter2092.QRCrypt;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

public class QRCryptFile {

	public static final byte[] MAGIC_NUMBER = "QRCr".getBytes();
	public static final int VERSION_NUMBER = 0x00;
	public static final int HAS_SIGNATURE = 0xFF;
	public static final int NO_SIGNATURE = 0x00;
	
	public static final int STREAM_BLOCK_SIZE = 2048;
	
	protected SecretKey masterKey;
	protected SecretKey aesKey;
	protected PrivateKey privateKey;
	protected PublicKey publicKey;
	protected IvParameterSpec masterKeyIV;
	protected IvParameterSpec aesKeyIV;
	protected byte[] signature;
	protected BufferedInputStream inputStream;
	protected ByteArrayOutputStream byteArrayOutputStream;
	
	public class PossiblyCompromisedQRCryptException extends Exception {
		private static final long serialVersionUID = -7668390109686437471L;
		private static final String MESSAGE = "The integrity of this QRCrypt file may have been compromised. The data in this QRCrypt file may not be the same data the sender was intending to send.";
	}
	
	public class MissingSignatureQRCryptException extends Exception {
		private static final long serialVersionUID = -7668390109686437471L;
		private static final String MESSAGE = "The integrity of this QRCrypt file cannot be verified because it is missing a signature. The data in this QRCrypt file may not be the same data the sender was intending to send.";
	}
	
	public QRCryptFile(SecretKey masterKey, SecretKey aesKey, PrivateKey privateKey, PublicKey publicKey, byte[] signature, BufferedInputStream inputStream, IvParameterSpec aesKeyIV) throws IOException {
		this.masterKey = masterKey;
		this.aesKey = aesKey;
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.signature = signature;
		this.inputStream = inputStream;
		this.aesKeyIV = aesKeyIV;
		
		this.byteArrayOutputStream = new ByteArrayOutputStream();
		byte[] byteArray = new byte[STREAM_BLOCK_SIZE];
		int bytesRead;
		while ((bytesRead = inputStream.read(byteArray)) != -1) {
			this.byteArrayOutputStream.write(Arrays.copyOf(byteArray, bytesRead));
		}
		this.byteArrayOutputStream.flush();
	}
	
	protected QRCryptFile() {
	}
	
	public byte[] getRawData() {
		return byteArrayOutputStream.toByteArray();
	}
	
	public void verify() throws MissingSignatureQRCryptException, NoSuchAlgorithmException, PossiblyCompromisedQRCryptException, NoSuchPaddingException, InvalidKeyException, IOException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher;
		MessageDigest md;
		byte[] byteArray;
		int bytesRead;
		ByteArrayInputStream inputStream = new ByteArrayInputStream(byteArrayOutputStream.toByteArray());
		
		md = MessageDigest.getInstance("SHA-256");
		if (!Arrays.equals(Arrays.copyOf(md.digest(publicKey.getEncoded()), 16), aesKey.getEncoded())) throw new PossiblyCompromisedQRCryptException();
		inputStream.skip(5);
		if (inputStream.read() == NO_SIGNATURE) throw new MissingSignatureQRCryptException();
		cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, publicKey);
		md.reset();
		System.out.println("Signature (compare 1): " + Main.bytesToHex(cipher.doFinal(signature)));
		System.out.println("Signature (compare 2): " + Main.bytesToHex(Arrays.copyOf(md.digest(this.byteArrayOutputStream.toByteArray()), 16)));
		if (!Arrays.equals(cipher.doFinal(signature), Arrays.copyOf(md.digest(this.byteArrayOutputStream.toByteArray()), 16))) throw new PossiblyCompromisedQRCryptException();
	}
	
	public void writeFileTo(BufferedOutputStream outputStream) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher1;
		Cipher cipher2;
		Cipher cipher3;
		MessageDigest md;
		byte[] byteArray;
		int bytesRead;
		
		outputStream.write(MAGIC_NUMBER); // 4 bytes
		outputStream.write(VERSION_NUMBER); // 1 byte
		outputStream.write(HAS_SIGNATURE); // 1 byte
		cipher1 = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher1.init(Cipher.ENCRYPT_MODE, masterKey);
		cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher2.init(Cipher.ENCRYPT_MODE, aesKey);
		cipher3 = Cipher.getInstance("RSA");
		cipher3.init(Cipher.ENCRYPT_MODE, privateKey);
		outputStream.write(cipher1.getIV()); // 16 bytes
		outputStream.write(cipher2.getIV()); // 16 bytes
		masterKeyIV = new IvParameterSpec(cipher1.getIV());
		aesKeyIV = new IvParameterSpec(cipher2.getIV());
		byteArray = cipher1.doFinal(concatenate(aesKey.getEncoded(), privateKey.getEncoded()));
		outputStream.write(new byte[] {(byte) (byteArray.length / 0x0100), (byte) (byteArray.length % 0x0100)});
		outputStream.write(byteArray); // 368 bytes
		byteArray = new byte[STREAM_BLOCK_SIZE];
		md = MessageDigest.getInstance("SHA-256");
		System.out.println(Main.bytesToHex(publicKey.getEncoded()));
		signature = cipher3.doFinal(Arrays.copyOf(md.digest(byteArrayOutputStream.toByteArray()), 16));
		System.out.println("Signature (write): " + Main.bytesToHex(signature));
		byte[] cipher2Data = concatenate(concatenate(concatenate(concatenate(new byte[] {(byte) (publicKey.getEncoded().length / 0x0100), (byte) (publicKey.getEncoded().length % 0x0100)}, publicKey.getEncoded()), new byte[] {(byte) (signature.length / 0x0100), (byte) (signature.length % 0x0100)}), signature), byteArrayOutputStream.toByteArray());
		outputStream.write(cipher2.doFinal(cipher2Data)); // Data
		outputStream.close();
	}
	
	protected byte[] concatenate(byte[] a, byte[] b) throws IOException {
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		outputStream.write(a);
		outputStream.write(b);
		return outputStream.toByteArray();
	}

}
