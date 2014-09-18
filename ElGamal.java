import java.security.*;
import javax.crypto.*;
import java.util.*;
import java.math.BigInteger;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteOrder;
import java.nio.ByteBuffer;

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
		
		byte[] key = keyDerivation(DHEncryptorKey.toByteArray(),10,"salt".getBytes("UTF-8"));
		
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
	public static byte[] keyDerivation(byte[] shortKey, int iterations, byte[] salt) throws GeneralSecurityException {
		int numPartials = 128/shortKey.length;
		byte[] key = new byte[128];
		byte[][] u = new byte[numPartials][];
		Mac mac = Mac.getInstance("HmacSHA256");
		
		for( int i = 0; i < numPartials; i++ ) {
			for( int j = 0; j < iterations-1; j++ ) {
				mac.init(new SecretKeySpec(shortKey,"HMACSHA256"));
				if( j == 0 ) {
					ByteBuffer bb = ByteBuffer.wrap(ByteBuffer.allocate(4).putInt(i).array());
					bb.order(ByteOrder.BIG_ENDIAN);
					u[j] = mac.doFinal(combineArrays(salt,bb.array()));

				} else
					u[j] = mac.doFinal(u[j-1]);
			}
			byte[] t = xorPartials(u);
			// copy the t partial into key
			u = new byte[numPartials][];
		}
		return key;
	}
	
	public static byte[] combineArrays(byte[]... arrays) {
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
	
	public static byte[] xorPartials(byte[][] array) {
		byte[] xoredArray = array[0];
		for( int i = 1; i < array.length; i++ ) {
			for( int j = 0; j < array[0].length; j++ ) {
				xoredArray[j] = (byte)(xoredArray[j] ^ array[i][j]);
			}
		}
		return xoredArray;
	}
	
	/*
	public BigInteger symmetricEncrypt( byte[] key, BigInteger message ) {
	}
	
	public BigInteger symmetricDecrypt( byte[] key, BigInteger cipher ) {
	}
	*/
}