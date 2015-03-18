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
	
	private class QRCryptVersionException extends Exception {
		private static final long serialVersionUID = 4501079070355740898L;
		private static final String MESSAGE = "This QRCrypt file is not compatible with this version of QRCrypt.";
		
		@Override
		public String getMessage() {
			return MESSAGE;
		}
	}
	
	public QRCryptFileReader(Path path) throws IOException, InvalidQRCryptFileException, QRCryptVersionException {
		reader = Files.newBufferedReader(path);
		readHeaders();
	}
	
	public void readHeaders() throws IOException, InvalidQRCryptFileException, QRCryptVersionException {
		CharBuffer buffer;
		
		// Magic number; is this really a QRCrypt file?
		buffer = CharBuffer.allocate(4);
		if (reader.read(buffer) != 4 || !buffer.equals(MAGIC_NUMBER)) throw new InvalidQRCryptFileException();
		
		// Version number; is the QRCrypt file version compatible with this version?
		buffer = CharBuffer.allocate(1);
		switch (buffer.charAt(0)) {
		case 0x00:
			break;
		default:
			throw new QRCryptVersionException();
		}
	}
	
	public void readPrivateData() {
		
	}

}
