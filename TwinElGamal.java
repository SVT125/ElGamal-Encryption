// TwinElGamal encryption using SHA-256 to encrypt messages with AES, prepends the cipher text with the IV.
// Mock program where the encryption method outputs both pk/sk where a1/a2 are the public exponents, b the private exponent.

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import java.util.*;
import java.math.BigInteger;
import java.io.UnsupportedEncodingException;

public class TwinElGamal extends ElGamal {
	public static void main(String[] args) throws Exception {
		String message = "The cat sours the basil";
		System.out.println(message);
		TwinElGamalKeyTriple output = encrypt(message);
		String decryption = decrypt(output);
		System.out.println(decryption);
	}
	
	public static TwinElGamalKeyTriple encrypt(String message) throws GeneralSecurityException, UnsupportedEncodingException {
		int order = 512; // the order of bits
		Random r = new Random();
		BigInteger p = findPrimeSet(order, r);
		BigInteger g = findGenerator(order, p, r);

		BigInteger a1 = randomSetNumber(order,p,r), a2 = randomSetNumber(order,p,r), b = randomSetNumber(order,p,r);
		
		BigInteger u = g.modPow(b,p);
		
		BigInteger h1 = g.modPow(a1,p), h2 = g.modPow(a2,p);

		BigInteger DHEncryptorKey = h1.modPow(b,p), DHEncryptorKey2 = h2.modPow(b,p);
		
		byte[] keyEncryptionArray = hashKey(u.toByteArray(),DHEncryptorKey.toByteArray(),DHEncryptorKey2.toByteArray());
		
		Cipher encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec encryptionKey = new SecretKeySpec(keyEncryptionArray,"AES");
		encryptor.init(Cipher.ENCRYPT_MODE,encryptionKey);
		
		byte[] messageBytes = message.getBytes("UTF-8");
		byte[] encryption = encryptor.doFinal(messageBytes);
		byte[] iv = encryptor.getIV();
		byte[] ciphertext = combineArrays(iv,encryption);
		
		KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
		DHPublicKey dpk = (DHPublicKey)keyFactory.generatePublic(new DHPublicKeySpec(u,p,g));
		DHPrivateKey dsk = (DHPrivateKey)keyFactory.generatePrivate(new DHPrivateKeySpec(a1,p,g));
		DHPrivateKey dsk2 = (DHPrivateKey)keyFactory.generatePrivate(new DHPrivateKeySpec(a2,p,g));
		
		return new TwinElGamalKeyTriple(ciphertext,dpk,dsk,dsk2);
	}
	
	public static String decrypt(TwinElGamalKeyTriple tekp) throws GeneralSecurityException {
		byte[] iv = tekp.deriveIV();
		byte[] cipher = tekp.deriveCiphertext();	
		
		KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
		
		DHPublicKeySpec publicKeySpec = keyFactory.getKeySpec(tekp.getPublicKey(), DHPublicKeySpec.class);
		
		BigInteger publicKey = publicKeySpec.getY();
		BigInteger privateKey = tekp.getPrivateKey().getX();
		BigInteger privateKey2 = tekp.getPrivateKey2().getX();
		BigInteger p = publicKeySpec.getP();
		BigInteger DHDecryptorKey = publicKey.modPow(privateKey,p);
		BigInteger DHDecryptorKey2 = publicKey.modPow(privateKey2,p);
		
		byte[] keyDecryptionArray = hashKey(publicKey.toByteArray(),DHDecryptorKey.toByteArray(),DHDecryptorKey2.toByteArray());		
	
		Cipher decryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec decryptionKey = new SecretKeySpec(keyDecryptionArray,"AES");
		decryptor.init(Cipher.DECRYPT_MODE,decryptionKey, new IvParameterSpec(iv));
		String decryption = new String(decryptor.doFinal(cipher));
		
		return decryption;
	}
}

class TwinElGamalKeyTriple extends ElGamalKeyTriple {
	private DHPrivateKey sk2;
	
	public TwinElGamalKeyTriple(byte[] packet, DHPublicKey dpk, DHPrivateKey dsk, DHPrivateKey dsk2) {
		super(packet,dpk,dsk);
		this.sk2 = dsk2;
	}

	public DHPrivateKey getPrivateKey2() { return this.sk2; }
}
