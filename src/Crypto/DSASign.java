package Crypto;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

public class DSASign {
	public static long[] signDoc(String fileName, int bitLength) throws Exception {
		// Generate DSA key pair
		long timesforSign[] = new long[3];
		KeyPairGenerator keyGen = KeyPairGenerator.getInstance("DSA");
		keyGen.initialize(bitLength, new SecureRandom());
		long timeForKeyGeneration1 = System.nanoTime();
		KeyPair keyPair = keyGen.generateKeyPair();

		// Save private key to file
		PrivateKey privateKey = keyPair.getPrivate();

		// Save public key to file
		PublicKey publicKey = keyPair.getPublic();
		long timeForKeyGeneration2 = System.nanoTime();
		ObjectOutputStream privateKeyOS = new ObjectOutputStream(new FileOutputStream("private.key"));
		privateKeyOS.writeObject(privateKey);
		privateKeyOS.close();
		ObjectOutputStream publicKeyOS = new ObjectOutputStream(new FileOutputStream("public.key"));
		publicKeyOS.writeObject(publicKey);
		publicKeyOS.close();

		// Sign file
		Signature signature = Signature.getInstance("SHA256withDSA");
		signature.initSign(privateKey);
		FileInputStream fis = new FileInputStream(fileName);
		BufferedInputStream bufin = new BufferedInputStream(fis);
		byte[] buffer = new byte[1024];
		int len;
		long timeForSign1 = System.nanoTime();
		while ((len = bufin.read(buffer)) >= 0) {
			signature.update(buffer, 0, len);
		}
		long timeForSign2 = System.nanoTime();
		bufin.close();
		byte[] signatureBytes = signature.sign();

		// Verify signature
		signature.initVerify(publicKey);
		fis = new FileInputStream(fileName);
		bufin = new BufferedInputStream(fis);
		buffer = new byte[1024];

		long timeForVerification1 = System.nanoTime();
		while (bufin.available() != 0) {
			int read = bufin.read(buffer);
			signature.update(buffer, 0, read);
		}
		boolean verified = signature.verify(signatureBytes);
		long timeForVerification2 = System.nanoTime();
		bufin.close();
		timesforSign[0] = timeForKeyGeneration2 - timeForKeyGeneration1;
		timesforSign[1] = timeForSign2 - timeForSign1;
		timesforSign[2] = timeForVerification2 - timeForVerification1;
		System.out.println("Signature verified for " + bitLength + " bits:" + verified);
		return timesforSign;
	}

}
