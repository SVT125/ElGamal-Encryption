// ElGamal encryption using SHA-256 to encrypt messages with AES, prepends the cipher text with the IV.
// Mock program where the encryption method outputs both pk/sk where a is the public exponent, b the private exponent.

import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;
import javax.crypto.interfaces.*;
import java.util.*;
import java.math.BigInteger;
import java.io.UnsupportedEncodingException;

public class ElGamal {
	public static void main(String[] args) throws Exception {
		String message = "The cat sours the basil";
		System.out.println(message);
		ElGamalKeyTriple output = encrypt(message);
		String decryption = decrypt(output);
		System.out.println(decryption);
	}
	
	public static ElGamalKeyTriple encrypt(String message) throws GeneralSecurityException, UnsupportedEncodingException {
		int order = 2048; // the order of bits
		Random r = new Random();
		BigInteger p = findPrimeSet(order, r);
		BigInteger g = findGenerator(order, p, r);

		BigInteger a = randomSetNumber(order,p,r), b = randomSetNumber(order,p,r);
		BigInteger u = g.modPow(b,p);
		
		BigInteger h = g.modPow(a,p);

		BigInteger DHEncryptorKey = h.modPow(b,p);
		
		byte[] keyEncryptionArray = hashKey(u.toByteArray(),DHEncryptorKey.toByteArray());
		
		Cipher encryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec encryptionKey = new SecretKeySpec(keyEncryptionArray,"AES");
		encryptor.init(Cipher.ENCRYPT_MODE,encryptionKey);
		
		byte[] messageBytes = message.getBytes("UTF-8");
		byte[] encryption = encryptor.doFinal(messageBytes);
		byte[] iv = encryptor.getIV();
		byte[] ciphertext = combineArrays(iv,encryption);
		
		KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
		DHPublicKey dpk = (DHPublicKey)keyFactory.generatePublic(new DHPublicKeySpec(u,p,g));
		DHPrivateKey dsk = (DHPrivateKey)keyFactory.generatePrivate(new DHPrivateKeySpec(a,p,g));
		
		return new ElGamalKeyTriple(ciphertext,dpk,dsk);
	}
	
	public static String decrypt(ElGamalKeyTriple ekp) throws GeneralSecurityException {
		byte[] iv = ekp.deriveIV();
		byte[] cipher = ekp.deriveCiphertext();	
		
		KeyFactory keyFactory = KeyFactory.getInstance("DiffieHellman");
		
		DHPublicKeySpec publicKeySpec = keyFactory.getKeySpec(ekp.getPublicKey(), DHPublicKeySpec.class);
		
		BigInteger publicKey = publicKeySpec.getY();
		BigInteger privateKey = ekp.getPrivateKey().getX();
		BigInteger p = publicKeySpec.getP();
		BigInteger DHDecryptorKey = publicKey.modPow(privateKey,p);
			
		byte[] keyDecryptionArray = hashKey(publicKey.toByteArray(),DHDecryptorKey.toByteArray());	
		
		Cipher decryptor = Cipher.getInstance("AES/CBC/PKCS5Padding");
		SecretKeySpec decryptionKey = new SecretKeySpec(keyDecryptionArray,"AES");
		decryptor.init(Cipher.DECRYPT_MODE,decryptionKey, new IvParameterSpec(iv));
		String decryption = new String(decryptor.doFinal(cipher));
		
		return decryption;
	}
	
	// Hashes the given arguments together with SHA-256.
	protected static byte[] hashKey(byte[]... values) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[][] hashedValues = new byte[values.length][];
		int hashLength = 0;
		for( int i = 0; i < hashedValues.length; i++ ) {
			byte[] hash = md.digest(values[i]);
			hashedValues[i] = hash;
			hashLength += hash.length;
		}
		byte[] finalHashArgument = combineArrays(hashedValues);
		return md.digest(finalHashArgument);
	}
	
	// We generate an n-bit safe prime for algorithm 4.86 such that p = 2q + 1 is a prime.
	protected static BigInteger findPrimeSet(int n, Random r) {
		BigInteger q = new BigInteger(n,r);
		boolean isPrime = false;
		BigInteger p = q.multiply(new BigInteger("2")).add(new BigInteger("1"));
		while(!isPrime) {
			if(p.isProbablePrime(48))
				isPrime = true;
			else {
				q = new BigInteger(n,r);
				p = q.multiply(new BigInteger("2")).add(new BigInteger("1"));
			}
		}
		
		return p;
	}

	// Finds the generator of the finite cyclic group mod n-bit prime, with specified certainty power for the Miller-Rabin primality test = 48.
	// We use algorithm 4.86 from HAC to find the generator given that the prime generated is p = 2q + 1.
	// The prime factorization of the group's order is 2q, so we do algorithm 4.80 checking powers 2 and q.	
	protected static BigInteger findGenerator(int n, BigInteger p, Random r) {
		boolean generatorFound = false;
		BigInteger one = new BigInteger("1");
		BigInteger q = p.subtract(one).divide(new BigInteger("2")); // recover q
		BigInteger guess = null;
		while(!generatorFound) {
			guess = randomSetNumber(n,p,r);
			if(!guess.isProbablePrime(48))
				continue;
			if(!guess.modPow(new BigInteger("2"),p).equals(one) && !guess.modPow(q,p).equals(one))
				generatorFound = true;
		}
		return guess;
	}
	
	// Returns a random number of the set of elements {0,...,p-1} by generating n-bit numbers then checking if within the set.
	protected static BigInteger randomSetNumber(int n, BigInteger p, Random r) {
		BigInteger random;
		while(true) {
			random = new BigInteger(n,r);
			if( random.compareTo(p) < 0)
				return random;
		}	
	}
	
	// Concatenates byte arrays together, in order of arguments listed.
	protected static byte[] combineArrays(byte[]... arrays) {
		int currentEndPos = arrays[0].length;
		int totalLength = 0;
		for( byte[] partial : arrays )
			totalLength += partial.length;
			
		byte[] result = new byte[totalLength];
		for( int i = 0; i < arrays.length; i++ ) {
			if(i == 0)
				System.arraycopy(arrays[i],0,result,0,currentEndPos);
			else
				System.arraycopy(arrays[i],0,result,currentEndPos,arrays[i].length);	
			
			currentEndPos = arrays[i].length;
		}
		return result;
	}
	
	// XOR's all the arrays together.
	protected static byte[] xorPartials(byte[][] array) {
		byte[] xoredArray = array[0];
		for( int i = 1; i < array.length; i++ ) {
			for( int j = 0; j < array[0].length; j++ ) {
				xoredArray[j] = (byte)(xoredArray[j] ^ array[i][j]);
			}
		}
		return xoredArray;
	}	
}

class ElGamalKeyTriple {
	protected byte[] packet;
	protected DHPublicKey pk;
	protected DHPrivateKey sk;
	
	public ElGamalKeyTriple(byte[] packet, DHPublicKey dpk, DHPrivateKey dsk) {
		this.packet = packet;
		this.pk = dpk;
		this.sk = dsk;
	}
	
	public byte[] deriveIV() { 
 		byte[] iv = Arrays.copyOfRange(this.packet,0,16); // assume 16 byte IV
		return iv;
	}
	public byte[] deriveCiphertext() {
		byte[] encryption = Arrays.copyOfRange(this.packet,16,this.packet.length);
		return encryption;
	}
	
	public DHPublicKey getPublicKey() { return this.pk; }
	public DHPrivateKey getPrivateKey() { return this.sk; }
}
