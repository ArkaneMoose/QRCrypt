package org.gatsa.chapter2092.QRCrypt;

import java.io.BufferedInputStream;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class QRCryptFileParser {
	
	public final SecretKey masterKey;
	public final SecretKey aesKey;
	public final PrivateKey privateKey;
	public final PublicKey publicKey;
	public final IvParameterSpec masterKeyIV;
	public final IvParameterSpec aesKeyIV;
	public final byte[] signature;
	public final BufferedInputStream inputStream;
	public final boolean hasSignature;
	
	public class InvalidQRCryptException extends Exception {
		private static final long serialVersionUID = -7668390109686437471L;
		private static final String MESSAGE = "This file is not a valid QRCrypt file.";
		
		@Override
		public String getMessage() {
			return MESSAGE;
		}
	}
	
	public class IncompatibleQRCryptException extends Exception {
		private static final long serialVersionUID = -7668390109686437471L;
		private static final String MESSAGE = "This file requires a newer version of QRCrypt.";
		
		@Override
		public String getMessage() {
			return MESSAGE;
		}
	} 
	
	public QRCryptFileParser(BufferedInputStream stream, byte[] masterKey) throws IOException, InvalidQRCryptException, IncompatibleQRCryptException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException, InvalidKeySpecException {
		byte[] byteArray;
		ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		ByteArrayOutputStream decryptedOutputStream;
		MessageDigest md;
		int bytesRead;
		int signatureLength;
		Cipher cipher;
		
		this.masterKey = new SecretKeySpec(masterKey, "AES");
		byteArray = new byte[4];
		stream.read(byteArray);
		if (!Arrays.equals(byteArray, QRCryptFile.MAGIC_NUMBER)) throw new InvalidQRCryptException();
		switch (stream.read()) { // Version number
		case 0x00:
			hasSignature = (stream.read() != 0);
			byteArray = new byte[16];
			stream.read(byteArray);
			masterKeyIV = new IvParameterSpec(Arrays.copyOf(byteArray, 16));
			byteArray = new byte[16];
			stream.read(byteArray);
			aesKeyIV = new IvParameterSpec(Arrays.copyOf(byteArray, 16));
			byteArray = new byte[2];
			stream.read(byteArray);
			byteArray = new byte[((byteArray[0] & 0xFF) * 0x0100) + (byteArray[1] & 0xFF)];
			stream.read(byteArray);
			cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
			cipher.init(Cipher.DECRYPT_MODE, this.masterKey, masterKeyIV);
			byteArray = cipher.doFinal(byteArray);
			aesKey = new SecretKeySpec(Arrays.copyOf(byteArray, 16), "AES");
			privateKey = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(Arrays.copyOfRange(byteArray, 16, byteArray.length)));
			byteArray = new byte[QRCryptFile.STREAM_BLOCK_SIZE];
			while ((bytesRead = stream.read(byteArray)) != -1) {
				outputStream.write(Arrays.copyOf(byteArray, bytesRead));
			}
			cipher.init(Cipher.DECRYPT_MODE, aesKey, aesKeyIV);
			decryptedOutputStream = new ByteArrayOutputStream();
			decryptedOutputStream.write(cipher.doFinal(outputStream.toByteArray()));
			byteArray = decryptedOutputStream.toByteArray();
			bytesRead = ((byteArray[0] & 0xFF) * 0x0100) + (byteArray[1] & 0xFF) + 2;
			signatureLength = ((byteArray[bytesRead] & 0xFF) * 0x0100) + (byteArray[bytesRead + 1] & 0xFF) + bytesRead + 2;
			System.out.println(bytesRead);
			System.out.println(byteArray[0]);
			System.out.println(byteArray[1]);
			System.out.println(Main.bytesToHex(Arrays.copyOfRange(byteArray, 2, bytesRead)));
			publicKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(Arrays.copyOfRange(byteArray, 2, bytesRead)));
			signature = Arrays.copyOfRange(byteArray, bytesRead + 2, signatureLength);
			System.out.println("Signature (read): " + Main.bytesToHex(signature));
			inputStream = new BufferedInputStream(new ByteArrayInputStream(Arrays.copyOfRange(byteArray, signatureLength, byteArray.length)));
			break;
		case -1:
			throw new InvalidQRCryptException();
		default:
			throw new IncompatibleQRCryptException();
		}
	}
	
	public QRCryptFile toQRCryptFile() throws IOException {
		return new QRCryptFile(masterKey, aesKey, privateKey, publicKey, signature, inputStream, aesKeyIV);
	}

}
