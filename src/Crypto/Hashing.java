package Crypto;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Hashing {

	public static long[] hash(String inputFile) {
		long timesForHash[] = new long[3];
		try {
			FileInputStream fis = new FileInputStream(inputFile);
			byte[] data = new byte[fis.available()];
			fis.read(data);
			fis.close();
			long timeForsha2561 = System.nanoTime();
			String sha256Hash = getHash(data, "SHA-256");
			long timeForsha2562 = System.nanoTime();
			long timeForsha5121 = System.nanoTime();
			String sha512Hash = getHash(data, "SHA-512");
			long timeForsha5122 = System.nanoTime();
			long timeForsha32561 = System.nanoTime();
			String sha3_256Hash = getHash(data, "SHA3-256");
			long timeForsha32562 = System.nanoTime();
			timesForHash[0] = timeForsha2562 - timeForsha2561;
			timesForHash[1] = timeForsha5122 - timeForsha5121;
			timesForHash[2] = timeForsha32562 - timeForsha32561;
			writeToFile(sha256Hash, "sha256Hash" + "_" + inputFile + ".dat");
			writeToFile(sha512Hash, "sha512Hash" + "_" + inputFile + ".dat");
			writeToFile(sha3_256Hash, "sha3_256Hash" + "_" + inputFile + ".dat");
		} catch (IOException | NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return timesForHash;
	}

	private static void writeToFile(String hashVal, String fileName) throws IOException {
		FileOutputStream outputStream = new FileOutputStream(fileName);
		byte[] strToBytes = hashVal.getBytes();
		outputStream.write(strToBytes);

		outputStream.close();
	}

	public static String getHash(byte[] data, String algorithm) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance(algorithm);
		byte[] hashBytes = md.digest(data);
		StringBuilder sb = new StringBuilder();
		for (byte b : hashBytes) {
			sb.append(String.format("%02x", b));
		}
		return sb.toString();
	}

}
