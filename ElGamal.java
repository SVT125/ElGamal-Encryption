import java.security.*;
import javax.crypto.*;
import java.math.BigInteger;
import java.util.Random;

class ElGamal {
	static int order = 2048;
	public static void main(String[] args) throws Exception {
		Random r = new Random();
		BigInteger p = findPrimeSet(order, r);
		System.out.println("Found p!");
		BigInteger g = findGenerator(order, p, r);
		System.out.println("Found g!");

		BigInteger a = randomSetNumber(order,p,r), b = randomSetNumber(order,p,r);
		
		BigInteger u = g.modPow(b,p); //sent to the decryptor
		
		BigInteger h = g.modPow(a,p);

		BigInteger DHEncryptorKey = h.modPow(b,p);
		BigInteger DHDecryptorKey = u.modPow(a,p);
		

		
		// to-do: encrypt the message, output from encryptor, etc.
	}
	
	// We generate an n-bit safe prime for algorithm 4.86 such that p = 2q + 1 is a prime.
	public static BigInteger findPrimeSet(int n, Random r) {
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
	public static BigInteger findGenerator(int n, BigInteger p, Random r) {
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
	public static BigInteger randomSetNumber(int n, BigInteger p, Random r) {
		BigInteger random;
		while(true) {
			random = new BigInteger(n,r);
			if( random.compareTo(p) < 0)
				return random;
		}	
	}
	
	// Uses PBKDF2 to derive a longer 128-bit key for AES.
	public static byte[] keyDerivation(byte[] shortKey, int iterations) {
		byte[] key = new byte[128];
		Mac mac = Mac.getInstance("HmacSHA256");
		for( int i = 0; i < 128/shortKey.length; i++ ) {
			for( int j = 0; j < iterations; j++ ) {
				mac.init(new SecretKeySpec(shortKey,"HMACSHA256"));
				byte[]  = mac.doFinal(DHEncryptorKey.toByteArray());
			}
		}
		return key;
	}
	
	/*
	public BigInteger symmetricEncrypt( byte[] key, BigInteger message ) {
		Cipher c = Cipher.getInstance("
	}
	
	public BigInteger symmetricDecrypt( byte[] key, BigInteger cipher ) {
	}
	*/
}