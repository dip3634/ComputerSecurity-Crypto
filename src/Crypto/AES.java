package Crypto;

import java.io.FileInputStream;
import java.io.FileOutputStream;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AES {

	public static void encryptCBC(SecretKey key, IvParameterSpec iv, String inputFile, String outputFile)
			throws Exception {
		// create a cipher object with AES in CBC mode
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		// read the input file and encrypt it
		FileInputStream in = new FileInputStream(inputFile);
		FileOutputStream out = new FileOutputStream(outputFile);
		byte[] inputBuffer = new byte[64];
		int bytesRead;
		while ((bytesRead = in.read(inputBuffer)) != -1) {
			byte[] outputBuffer = cipher.update(inputBuffer, 0, bytesRead);
			if (outputBuffer != null) {
				out.write(outputBuffer);
			}
		}
		byte[] outputBuffer = cipher.doFinal();

		if (outputBuffer != null) {
			out.write(outputBuffer);
		}
		in.close();
		out.close();
	}

	public static void decryptCBC(SecretKey key, IvParameterSpec iv, String inputFile, String outputFile)
			throws Exception {
		// create a cipher object with AES in CBC mode
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);

		// read the input file and decrypt it
		FileInputStream in = new FileInputStream(inputFile);
		FileOutputStream out = new FileOutputStream(outputFile);
		byte[] inputBuffer = new byte[64];
		int bytesRead;
		while ((bytesRead = in.read(inputBuffer)) != -1) {
			byte[] outputBuffer = cipher.update(inputBuffer, 0, bytesRead);
			if (outputBuffer != null) {
				out.write(outputBuffer);
			}
		}
		byte[] outputBuffer = cipher.doFinal();
		if (outputBuffer != null) {
			out.write(outputBuffer);
		}
		in.close();
		out.close();
	}

	public static void encryptCTR(SecretKey key, IvParameterSpec iv, String inputFile, String outputFile)
			throws Exception {
		// create a cipher object with AES in CTR mode
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		// read the input file and encrypt it
		FileInputStream in = new FileInputStream(inputFile);
		FileOutputStream out = new FileOutputStream(outputFile);
		byte[] inputBuffer = new byte[64];
		int bytesRead;
		while ((bytesRead = in.read(inputBuffer)) != -1) {
			byte[] outputBufferCTR = cipher.update(inputBuffer, 0, bytesRead);
			if (outputBufferCTR != null) {
				out.write(outputBufferCTR);
			}
		}
		byte[] outputBuffer = cipher.doFinal();

		if (outputBuffer != null) {
			out.write(outputBuffer);
		}
		in.close();
		out.close();
	}

	public static void decryptCTR(SecretKey key, IvParameterSpec iv, String inputFile, String outputFile)
			throws Exception {
		// create a cipher object with AES in CTR mode
		Cipher cipher = Cipher.getInstance("AES/CTR/NoPadding");
		cipher.init(Cipher.DECRYPT_MODE, key, iv);

		// read the input file and decrypt it
		FileInputStream in = new FileInputStream(inputFile);
		FileOutputStream out = new FileOutputStream(outputFile);
		byte[] inputBuffer = new byte[64];
		int bytesRead;
		while ((bytesRead = in.read(inputBuffer)) != -1) {
			byte[] outputBuffer = cipher.update(inputBuffer, 0, bytesRead);
			if (outputBuffer != null) {
				out.write(outputBuffer);
			}
		}
		byte[] outputBuffer = cipher.doFinal();
		if (outputBuffer != null) {
			out.write(outputBuffer);
		}
		in.close();
		out.close();
	}
}