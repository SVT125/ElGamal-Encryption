class RandomUtils {
	// Uses PBKDF2 to derive a longer 128-bit key for AES, the PRF is HMAC-SHA256.
	public static byte[] keyDerivation(byte[] shortKey, int iterations, byte[] salt) throws GeneralSecurityException {
		int numPartials = 128/shortKey.length;
		int currentEndPos = 0;
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
			
			System.arraycopy(t,0,key,i * shortKey.length,(i+1) * shortKey.length);
			
			u = new byte[numPartials][];
		}
		return key;
	}
}