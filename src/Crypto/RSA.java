package Crypto;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.Cipher;

public class RSA {
	public static long[] RSAEncrypt(String inputFile, int bitLength, int encChunkSize, int decChunkSize,
			String encryptedFileforRSA2048, String decryptedFileforRSA2048) {
		long retArray[] = new long[2];
		try {
			// Generate a 2048-bit RSA key pair

			KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
			keyPairGen.initialize(bitLength);
			long timeForRSAKey1 = System.nanoTime();
			KeyPair keyPair = keyPairGen.generateKeyPair();
			PublicKey publicKey = keyPair.getPublic();
			PrivateKey privateKey = keyPair.getPrivate();
			long timeForRSAKey2 = System.nanoTime();
			if (inputFile.charAt(9) != '1')
				System.out.println("RSA " + bitLength + " bit key generation time:"
						+ String.valueOf(timeForRSAKey2 - timeForRSAKey1));
			// Initialize the cipher
			Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
			// Encrypt a file
			FileInputStream in = new FileInputStream(inputFile);
			FileOutputStream out = new FileOutputStream(encryptedFileforRSA2048);
			cipher.init(Cipher.ENCRYPT_MODE, publicKey);
			byte[] input = new byte[encChunkSize];
			int bytesRead;
			long timeForRSAEncryption1 = System.nanoTime();
			while ((bytesRead = in.read(input)) != -1) {
				byte[] output = cipher.doFinal(input, 0, bytesRead);
				if (output != null)
					out.write(output);
			}
			long timeForRSAEncryption2 = System.nanoTime();
			in.close();
			out.close();
			retArray[0] = timeForRSAEncryption2 - timeForRSAEncryption1;
			retArray[1] = RSADecrypt(encryptedFileforRSA2048, decryptedFileforRSA2048, privateKey, decChunkSize);
			// Decrypt the file

		} catch (Exception e) {
			e.printStackTrace();
		}
		return retArray;

	}

	public static long RSADecrypt(String encryptedFileforRSA2048, String decryptedFileforRSA2048, PrivateKey privateKey,
			int decChunkSize) throws Exception {
		FileInputStream in = new FileInputStream(encryptedFileforRSA2048);
		FileOutputStream out = new FileOutputStream(decryptedFileforRSA2048);
		Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWITHSHA-256ANDMGF1PADDING");
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		byte[] cipherInput = new byte[decChunkSize];
		int bytesRead;
		long timeForRSAEncryption1 = System.nanoTime();
		while ((bytesRead = in.read(cipherInput)) != -1) {
			byte[] cipherOutput = cipher.doFinal(cipherInput, 0, bytesRead);
			if (cipherOutput != null)
				out.write(cipherOutput);
		}
		long timeForRSAEncryption2 = System.nanoTime();
		in.close();
		out.close();
		return timeForRSAEncryption2 - timeForRSAEncryption1;
	}
}
