package Crypto;

import java.security.SecureRandom;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class Driver {

	public static void main(String[] args) throws Exception {
		// the file to encrypt
		String inputFile = "plaintext.txt";
		String inputFile10 = "plaintext10.txt";
		String inputFile1 = "plaintext1.txt";
		// the encrypted file for CBC mode
		String encryptedFile = "encrypted.txt";
		// the decrypted file for CBC mode
		String decryptedFile = "decrypted.txt";
		// the encrypted file for CBC mode
		String encryptedFile10 = "encrypted10.txt";
		// the decrypted file for CBC mode
		String decryptedFile10 = "decrypted10.txt";
		// the encrypted file for CTR mode
		String encryptedFileforCTR = "encryptedCTR.txt";
		// the decrypted file for CTR mode
		String decryptedFileforCTR = "decryptedCTR.txt";
		// the encrypted file for CTR mode
		String encryptedFileforCTR10 = "encryptedCTR10.txt";
		// the decrypted file for CTR mode
		String decryptedFileforCTR10 = "decryptedCTR10.txt";
		// the encrypted file for CTR mode with 256bit
		String encryptedFileforCTR256 = "encryptedCTR256.txt";
		// the decrypted file for CTR mode with 256bit
		String decryptedFileforCTR256 = "decryptedCTR256.txt";
		// the encrypted file for CTR mode with 256bit
		String encryptedFileforCTR25610 = "encryptedCTR25610.txt";
		// the decrypted file for CTR mode with 256bit
		String decryptedFileforCTR25610 = "decryptedCTR25610.txt";
		String encryptedFileforRSA2048 = "encryptedFileforRSA2048.txt";
		String decryptedFileforRSA2048 = "decryptedFileforRSA2048.txt";
		String encryptedFileforRSA3072 = "encryptedFileforRSA3072.txt";
		String decryptedFileforRSA3072 = "decryptedFileforRSA3072.txt";
		String encryptedFileforRSA2048_1 = "encryptedFileforRSA2048_1.txt";
		String decryptedFileforRSA2048_1 = "decryptedFileforRSA2048_1.txt";
		String encryptedFileforRSA3072_1 = "encryptedFileforRSA3072_1.txt";
		String decryptedFileforRSA3072_1 = "decryptedFileforRSA3072_1.txt";
		double totalSize = 11201307;
		double smallFile=1307;
		double largeFile=11200000;
		double MBFile=1120000;
		// generate a 128-bit AES key
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		long timeForAESKey1 = System.nanoTime();
		SecretKey key = keyGen.generateKey();
		long timeForAESKey2 = System.nanoTime();
		System.out.println("AES 128 bit key generation time:" + String.valueOf(timeForAESKey2 - timeForAESKey1));
		// generate a random IV (Initialization Vector)
		SecureRandom random = new SecureRandom();
		byte[] ivBytes = new byte[16];
		random.nextBytes(ivBytes);
		IvParameterSpec iv = new IvParameterSpec(ivBytes);

		// encrypt the file for CBC mode
		long timeforAESCBCEncryption1 = System.nanoTime();
		AES.encryptCBC(key, iv, inputFile, encryptedFile);
		long timeforAESCBCEncryption2 = System.nanoTime();

		// decrypt the file for CBC mode
		long timeforAESCBCDecryption1 = System.nanoTime();
		AES.decryptCBC(key, iv, encryptedFile, decryptedFile);
		long timeforAESCBCDecryption2 = System.nanoTime();

		// encrypt the file for CTR mode
		long timeforAESCTREncryption1 = System.nanoTime();
		AES.encryptCTR(key, iv, inputFile, encryptedFileforCTR);
		long timeforAESCTREncryption2 = System.nanoTime();

		// decrypt the file for CTR mode
		long timeforAESCTRDecryption1 = System.nanoTime();
		AES.decryptCTR(key, iv, encryptedFileforCTR, decryptedFileforCTR);
		long timeforAESCTRDecryption2 = System.nanoTime();

		keyGen.init(256);
		long timeForAESKey2561 = System.nanoTime();
		key = keyGen.generateKey();
		long timeForAESKey2562 = System.nanoTime();
		System.out.println("AES 256 bit key generation time:" + String.valueOf(timeForAESKey2562 - timeForAESKey2561));
		// encrypt the file for CTR mode 256
		long timeforAESCTR256Encryption1 = System.nanoTime();
		AES.encryptCTR(key, iv, inputFile, encryptedFileforCTR256);
		long timeforAESCTR256Encryption2 = System.nanoTime();

		// decrypt the file for CTR mode 256
		long timeforAESCTR256Decryption1 = System.nanoTime();
		AES.decryptCTR(key, iv, encryptedFileforCTR256, decryptedFileforCTR256);
		long timeforAESCTR256Decryption2 = System.nanoTime();

		long[] timesforRSA2048Small = RSA.RSAEncrypt(inputFile, 2048, 190, 256, encryptedFileforRSA2048,
				decryptedFileforRSA2048);

		long[] timesforRSA3072Small = RSA.RSAEncrypt(inputFile, 3072, 190, 384, encryptedFileforRSA3072,
				decryptedFileforRSA3072);

		// decrypt the file for CBC mode
		// RSA.RSA2048Decrypt(encryptedFileforRSA2048, decryptedFileforRSA2048);

		long hashTimes1[] = Hashing.hash(inputFile);
		long timesForSign20481[] = DSASign.signDoc(inputFile, 2048);
		long timesForSign30721[] = DSASign.signDoc(inputFile, 3072);

		keyGen.init(128);
		key = keyGen.generateKey();

		// encrypt the file for CBC mode 10mb
		long timeforAESCBCEncryption101 = System.nanoTime();
		AES.encryptCBC(key, iv, inputFile10, encryptedFile10);
		long timeforAESCBCEncryption102 = System.nanoTime();

		// decrypt the file for CBC mode 10mb
		long timeforAESCBCDecryption101 = System.nanoTime();
		AES.decryptCBC(key, iv, encryptedFile10, decryptedFile10);
		long timeforAESCBCDecryption102 = System.nanoTime();

		// encrypt the file for CTR mode
		long timeforAESCTREncryption101 = System.nanoTime();
		AES.encryptCTR(key, iv, inputFile, encryptedFileforCTR10);
		long timeforAESCTREncryption102 = System.nanoTime();

		// decrypt the file for CTR mode
		long timeforAESCTRDecryption101 = System.nanoTime();
		AES.decryptCTR(key, iv, encryptedFileforCTR10, decryptedFileforCTR10);
		long timeforAESCTRDecryption102 = System.nanoTime();

		keyGen.init(256);
		key = keyGen.generateKey();

		// encrypt the file for CTR mode 256
		long timeforAESCTR256Encryption101 = System.nanoTime();
		AES.encryptCTR(key, iv, inputFile10, encryptedFileforCTR25610);
		long timeforAESCTR256Encryption102 = System.nanoTime();

		// decrypt the file for CTR mode 256
		long timeforAESCTR256Decryption101 = System.nanoTime();
		AES.decryptCTR(key, iv, encryptedFileforCTR25610, decryptedFileforCTR25610);
		long timeforAESCTR256Decryption102 = System.nanoTime();

		long[] timesforRSA2048Large = RSA.RSAEncrypt(inputFile1, 2048, 190, 256, encryptedFileforRSA2048_1,
				decryptedFileforRSA2048_1);

		long[] timesforRSA3072Large = RSA.RSAEncrypt(inputFile1, 3072, 190, 384, encryptedFileforRSA3072_1,
				decryptedFileforRSA3072_1);

		// decrypt the file for CBC mode
		// RSA.RSA2048Decrypt(encryptedFileforRSA2048, decryptedFileforRSA2048);

		long hashTimes2[] = Hashing.hash(inputFile10);
		long timesForSign20482[] = DSASign.signDoc(inputFile10, 2048);
		long timesForSign30722[] = DSASign.signDoc(inputFile10, 3072);

		System.out.println("AES CBC mode 1KB Encryption time: "
				+ String.valueOf((timeforAESCBCEncryption2 - timeforAESCBCEncryption1)
						));
		System.out.println("AES CBC mode 10MB Encryption time: "
				+ String.valueOf(timeforAESCBCEncryption102 - timeforAESCBCEncryption101));
		System.out.println("AES CBC mode 1KB Decryption time: "
				+ String.valueOf(timeforAESCBCDecryption2 - timeforAESCBCDecryption1)
						);
		
		System.out.println("AES CBC mode 10MB Decryption time: "
						+ (timeforAESCBCDecryption102 - timeforAESCBCDecryption101));
		
		System.out.println("AES CTR mode 1KB Encryption time: "
				+ String.valueOf((timeforAESCTREncryption2 - timeforAESCTREncryption1)));
		
		System.out.println("AES CTR mode 10MB Encryption time: "
				+ String.valueOf((timeforAESCTREncryption102 - timeforAESCTREncryption101)));

		System.out.println("AES CTR mode 1KB Decryption time: "
				+ String.valueOf((timeforAESCTRDecryption2 - timeforAESCTRDecryption1)));
		
		System.out.println("AES CTR mode 10MB Decryption time: "
				+ String.valueOf((timeforAESCTRDecryption102 - timeforAESCTRDecryption101)));

		System.out.println("AES CTR 256 mode 1KB Encryption time: "
				+ String.valueOf((timeforAESCTR256Encryption2 - timeforAESCTR256Encryption1)));
		
		System.out.println("AES CTR 256 mode 10MB Encryption time: "
				+ String.valueOf(
						+ (timeforAESCTR256Encryption102 - timeforAESCTR256Encryption101)));

		System.out.println("AES CTR 256 mode 1KB Decryption time: "
				+ String.valueOf((timeforAESCTR256Decryption2 - timeforAESCTR256Decryption1)));
		
		System.out.println("AES CTR 256 mode 10MB Decryption time: "
				+ String.valueOf(
						+ (timeforAESCTR256Decryption102 - timeforAESCTR256Decryption101)));


		System.out.println("RSA 2048 mode 10MB Encryption time: "
				+ String.valueOf(timesforRSA2048Large[0] ));

		System.out.println("RSA 2048 mode 10MB Decryption time: "
				+ String.valueOf(timesforRSA2048Large[1]));

		System.out.println("RSA 3072 mode 10MB Encryption time: "
				+ String.valueOf(timesforRSA3072Large[0] ));

		System.out.println("RSA 3072 mode 10MB Decryption time: "
				+ String.valueOf(timesforRSA3072Large[1]));
		
		System.out.println("RSA 2048 mode 1KB Encryption time: "
				+ String.valueOf(timesforRSA2048Small[0] ));

		System.out.println("RSA 2048 mode 1KB Decryption time: "
				+ String.valueOf(timesforRSA2048Small[1]));

		System.out.println("RSA 3072 mode 1KB Encryption time: "
				+ String.valueOf(timesforRSA3072Small[0] ));

		System.out.println("RSA 3072 mode 1KB Decryption time: "
				+ String.valueOf(timesforRSA3072Small[1]));
		
		

		System.out.println("AES CBC mode 1KB Encryption speed: "
				+ String.valueOf(smallFile / ((double)(timeforAESCBCEncryption2 - timeforAESCBCEncryption1)
						)));
		
		System.out.println("AES CBC mode 10MB Encryption speed: "
				+ String.valueOf(largeFile / ((double)(timeforAESCBCEncryption102 - timeforAESCBCEncryption101)
						)));

		System.out.println("AES CBC mode 1KB Decryption speed: "
				+ String.valueOf(smallFile / ((double)(timeforAESCBCDecryption2 - timeforAESCBCDecryption1)
						)));
		
		System.out.println("AES CBC mode 10MB Decryption speed: "
				+ String.valueOf(largeFile / ((double)(timeforAESCBCDecryption102 - timeforAESCBCDecryption101)
						)));
		
		System.out.println("AES CTR mode 1KB Encryption speed: "
				+ String.valueOf(smallFile / ((double)(timeforAESCTREncryption2 - timeforAESCTREncryption1)
						)));
		
		System.out.println("AES CTR mode 10MB Encryption speed: "
				+ String.valueOf(largeFile / ((double)(timeforAESCTREncryption102 - timeforAESCTREncryption101)
						)));

		System.out.println("AES CTR mode 1KB Decryption speed: "
				+ String.valueOf(smallFile / ((double)(timeforAESCTRDecryption2 - timeforAESCTRDecryption1)
						)));
		
		System.out.println("AES CTR mode 10MB Decryption speed: "
				+ String.valueOf(largeFile / ((double)(timeforAESCTRDecryption102 - timeforAESCTRDecryption101)
						)));

		System.out.println("AES CTR 256 mode 1KB Encryption speed: "
				+ String.valueOf(smallFile / ((double)(timeforAESCTR256Encryption2 - timeforAESCTR256Encryption1)
						)));
		
		System.out.println("AES CTR 256 mode 10MB Encryption speed: "
				+ String.valueOf(largeFile / ((double)
						+ (timeforAESCTR256Encryption102 - timeforAESCTR256Encryption101))));

		System.out.println("AES CTR 256 mode 1KB Decryption speed: "
				+ String.valueOf(smallFile / ((double)(timeforAESCTR256Decryption2 - timeforAESCTR256Decryption1)
						)));
		
		System.out.println("AES CTR 256 mode 10MB Decryption speed: "
				+ String.valueOf(largeFile / ((double)(timeforAESCTR256Decryption102 - timeforAESCTR256Decryption101)
						)));

		System.out.println("RSA 2048 mode 1KB Encryption speed: "
				+ String.valueOf(smallFile / ((double)((timesforRSA2048Small[0])))));
		
		System.out.println("RSA 2048 mode 1MB Encryption speed: "
				+ String.valueOf(MBFile / ((double)((timesforRSA2048Large[0])))));


		System.out.println("RSA 2048 mode 1KB Decryption speed: "
				+ String.valueOf(smallFile / ((double)(timesforRSA2048Small[1]))));
		
		System.out.println("RSA 2048 mode 10MB Decryption speed: "
				+ String.valueOf(MBFile / ((double)(timesforRSA2048Large[1]))));

		System.out.println("RSA 3072 mode 1KB Encryption speed: "
				+ String.valueOf(smallFile / ((double)(timesforRSA3072Small[0]))));
		
		System.out.println("RSA 3072 mode 10MB Encryption speed: "
				+ String.valueOf(largeFile / ((double)(timesforRSA3072Large[0]))));

		System.out.println("RSA 3072 mode 1KB Decryption speed: "
				+ String.valueOf(smallFile / ((double)(timesforRSA3072Small[1]))));
		
		System.out.println("RSA 3072 mode 10MB Decryption speed: "
				+ String.valueOf(largeFile / ((double)(timesforRSA3072Large[1]))));

		System.out.println("SHA 256 1KB hashing time: " + String.valueOf((hashTimes1[0])));

		System.out.println("SHA 512 1KB hashing time: " + String.valueOf((hashTimes1[1])));

		System.out.println("SHA3_256 1KB hashing time: " + String.valueOf((hashTimes1[2])));
		
		System.out.println("SHA 256 10MB hashing time: " + String.valueOf((hashTimes2[0])));

		System.out.println("SHA 512 10MB hashing time: " + String.valueOf((hashTimes2[1])));

		System.out.println("SHA3_256 10MB hashing time: " + String.valueOf((hashTimes2[2])));

		System.out.println(
				"SHA 256 hashing per byte time: " + String.valueOf((double)((hashTimes1[0] + hashTimes2[0]) / totalSize)));

		System.out.println(
				"SHA 512 hashing per byte time: " + String.valueOf((double)((hashTimes1[1] + hashTimes2[1]) / totalSize)));

		System.out.println(
				"SHA3_256 hashing per byte time: " + String.valueOf((double)((hashTimes1[2] + hashTimes2[2]) / totalSize)));

		System.out.println("Key generation time for DSA 2048: " + String.valueOf((double)((timesForSign20481[0]))));

		System.out.println(
				"1KB signature time for DSA 2048: " + String.valueOf((timesForSign20481[1])));

		System.out.println(
				"10MB signature time for DSA 2048: " + String.valueOf(timesForSign20482[1]));

		
		System.out.println("1KB verification time for DSA 2048: "
				+ String.valueOf((timesForSign20481[2])));
		
		System.out.println("10MB verification time for DSA 2048: "
				+ String.valueOf((timesForSign20482[2])));

		System.out.println("Time/byte for verification for 1KB DSA 2048: "
				+ String.valueOf((double)((timesForSign20481[2])) / smallFile));
		
		System.out.println("Time/byte for verification for 10MB DSA 2048: "
				+ String.valueOf((double)((timesForSign20482[2])) / largeFile));

		System.out.println("Time/byte for signature for 1KB DSA 2048: "
				+ String.valueOf((double)((timesForSign20481[1])) / smallFile));
		
		System.out.println("Time/byte for signature for 10MB DSA 2048: "
				+ String.valueOf((double)((timesForSign20482[1])) / largeFile));

		System.out.println("Key generation time for DSA 3072: " + String.valueOf((timesForSign30721[0])));

		System.out.println(
				"Signature time for 1KB DSA 3072: " + String.valueOf((timesForSign30721[1])));
		
		System.out.println(
				"Signature time for 10MB DSA 3072: " + String.valueOf((timesForSign30722[1])));

		System.out.println("Verification time for 1KB DSA 3072: "
				+ String.valueOf((timesForSign30721[2])));
		
		System.out.println("Verification time for 10MB DSA 3072: "
				+ String.valueOf((timesForSign30722[2])));

		System.out.println("Time/byte for verification for 1KB DSA 3072: "
				+ String.valueOf((double)((timesForSign30721[2])) / smallFile));

		System.out.println("Time/byte for verification for 10MB DSA 3072: "
				+ String.valueOf((double)((timesForSign30722[2])) / largeFile));

		System.out.println("Time/byte for signature for 1KB DSA 3072: "
				+ String.valueOf((double)((timesForSign30721[1])) / smallFile));
		
		System.out.println("Time/byte for signature for 10MB DSA 3072: "
				+ String.valueOf((double)((timesForSign30722[1])) / largeFile));

	}

}
