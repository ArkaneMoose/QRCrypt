package org.gatsa.chapter2092.QRCrypt;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.*;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class UnsignedQRCryptFile extends QRCryptFile {
	
	protected byte[] masterKeyBlock;
	
	public UnsignedQRCryptFile(SecretKey aesKey, PublicKey publicKey, byte[] signature, BufferedInputStream inputStream, byte[] masterKeyBlock, IvParameterSpec masterKeyIV, IvParameterSpec aesKeyIV) throws IOException {
		this.aesKey = aesKey;
		this.aesKeyIV = aesKeyIV;
		this.publicKey = publicKey;
		this.signature = signature;
		this.inputStream = inputStream;
		this.masterKeyBlock = this.masterKeyBlock;
		
		this.byteArrayOutputStream = new ByteArrayOutputStream();
		byte[] byteArray = new byte[STREAM_BLOCK_SIZE];
		int bytesRead;
		while ((bytesRead = inputStream.read(byteArray)) != -1) {
			this.byteArrayOutputStream.write(Arrays.copyOf(byteArray, bytesRead));
		}
		this.byteArrayOutputStream.flush();
	}

	@Override
	public void writeFileTo(BufferedOutputStream outputStream) throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher1;
		Cipher cipher2;
		Cipher cipher3;
		ByteArrayOutputStream totalBytes = new ByteArrayOutputStream();
		byte[] byteArray;
		int bytesRead;
		
		outputStream.write(MAGIC_NUMBER); // 4 bytes
		outputStream.write(VERSION_NUMBER); // 1 byte
		outputStream.write(NO_SIGNATURE); // 1 byte
		cipher2 = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher2.init(Cipher.ENCRYPT_MODE, aesKey);
		outputStream.write(masterKeyIV.getIV()); // 16 bytes
		outputStream.write(cipher2.getIV()); // 16 bytes
		aesKeyIV = new IvParameterSpec(cipher2.getIV());
		byteArray = masterKeyBlock;
		outputStream.write(new byte[] {(byte) (byteArray.length / 0x0100), (byte) (byteArray.length % 0x0100)});
		outputStream.write(byteArray); // 368 bytes
		byteArray = new byte[STREAM_BLOCK_SIZE];
		totalBytes.write(new byte[] {(byte) (publicKey.getEncoded().length / 0x0100), (byte) (publicKey.getEncoded().length % 0x0100)});
		totalBytes.write(publicKey.getEncoded()); // 94 bytes
		totalBytes.write(byteArrayOutputStream.toByteArray());
		cipher2.update(signature); // 16 bytes (signature)
		outputStream.write(cipher2.doFinal(totalBytes.toByteArray())); // Data
		outputStream.close();
	}
}
