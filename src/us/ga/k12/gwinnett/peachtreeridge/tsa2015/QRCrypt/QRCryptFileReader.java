package us.ga.k12.gwinnett.peachtreeridge.tsa2015.QRCrypt;

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.CharBuffer;
import java.nio.file.Files;
import java.nio.file.Path;

import javax.crypto.Cipher;

public class QRCryptFileReader {

	private static final CharBuffer MAGIC_NUMBER = CharBuffer.wrap("QRCr");
	
	private BufferedReader reader;
	private Cipher publicKey;
	
	private class InvalidQRCryptFileException extends Exception {
		private static final long serialVersionUID = 853629552928356093L;
		private static final String MESSAGE = "This file is not a valid QRCrypt file.";
		
		@Override
		public String getMessage() {
			return MESSAGE;
		}
	}
	
	public QRCryptFileReader(Path path) throws IOException, InvalidQRCryptFileException {
		reader = Files.newBufferedReader(path);
		readHeaders();
	}
	
	public void readHeaders() throws IOException, InvalidQRCryptFileException {
		CharBuffer magicNumber = CharBuffer.allocate(4);
		if (reader.read(magicNumber) != 4 || !magicNumber.equals(MAGIC_NUMBER)) throw new InvalidQRCryptFileException();
		//reader.read(publicKey);
		//Cipher.getInstance("AES_256/")
	}

}
