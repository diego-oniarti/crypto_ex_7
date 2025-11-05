package org.example;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Random;

/**
 * A vulnerable (and trivial) implementation
 * of RSA PKCS1 v1.5 using the BigInteger class.
 */
public class RSAPKCS1 {
    public final BigInteger modulus;
    public final BigInteger publicExponent;
    public final BigInteger privateExponent;

    /**
     * Generate a pair of RSA keys and stores them in the
     * class fields "publicExponent" and "privateExponent".
     * The public exponent is always 65537.
     * @param bitLength the length (e.g., 1024, 2048)
     */
    public RSAPKCS1(int bitLength) {
        Random random = new Random();
        random.setSeed(System.currentTimeMillis());

        BigInteger p = BigInteger.probablePrime(bitLength / 2, random);
        BigInteger q = BigInteger.probablePrime(bitLength / 2, random);

        // The modulus is p multiplied by q.
        modulus = p.multiply(q);

        // Compute the Euler totient function by multiplying (p-1) and (q-1).
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));

        // Define the public exponent (known value).
        publicExponent = new BigInteger("65537");

        // Compute the private exponent as e^(-1) mod phi.
        privateExponent = publicExponent.modInverse(phi);
    }

    /**
     * Encrypt a plaintext.
     * @param message the plaintext to encrypt
     * @return the ciphertext
     */
    public BigInteger encrypt(byte[] message) {
        byte[] padded = padMessage(message, (modulus.bitLength() + 7) / 8);
        return new BigInteger(1, padded).modPow(publicExponent, modulus);
    }

    /**
     * Decrypt an encrypted message.
     * @param encryptedMessage the ciphertext to decrypt
     * @return the plaintext
     */
    public byte[] decrypt(BigInteger encryptedMessage) {
        byte[] padded = encryptedMessage.modPow(privateExponent, modulus).toByteArray();
        int blockSize = (modulus.bitLength() + 7) / 8;

        if (padded.length < blockSize) {
            byte[] tmp = new byte[blockSize];
            System.arraycopy(padded, 0, tmp, blockSize - padded.length, padded.length);
            padded = tmp;
        } else if (padded.length > blockSize) {
            padded = Arrays.copyOfRange(padded, padded.length - blockSize, padded.length);
        }

        return unpadMessage(padded);
    }


    /**
     * PKCS#1 v1.5 padding for encryption. In PKCS#1 v1.5,
     * a message m is padded as 0x00||0x02||r||0x00||m
     * (where r is random).
     * @param message the plaintext as byte array
     * @param blockSize the side of the block
     * @return the padded plaintext as a byte array
     */
    private byte[] padMessage(byte[] message, int blockSize) {
        if (message.length > blockSize - 11) {
            throw new IllegalArgumentException("Message too long for RSA PKCS#1 padding");
        }

        byte[] padded = new byte[blockSize];
        padded[0] = 0x00;
        padded[1] = 0x02;

        // Fill padding with non-zero random bytes
        int padLength = blockSize - message.length - 3;
        byte[] padding = new byte[padLength];
        do {
            new Random().nextBytes(padding);
            for (int i = 0; i < padLength; i++) {
                if (padding[i] == 0) padding[i] = 1; // ensure non-zero
            }
        } while (Arrays.equals(padding, new byte[padLength]));

        System.arraycopy(padding, 0, padded, 2, padLength);
        padded[2 + padLength] = 0x00;
        System.arraycopy(message, 0, padded, 3 + padLength, message.length);
        return padded;
    }

    /**
     * PKCS#1 v1.5 (un)padding after decryption.
     * @param padded the padded plaintext
     * @return the padded plaintext as a byte array
     */
    private byte[] unpadMessage(byte[] padded) {
        if (padded[0] != 0x00 || padded[1] != 0x02) {
            throw new IllegalArgumentException("Invalid PKCS#1 padding");
        }

        int i = 2;
        while (padded[i] != 0x00) {
            i++;
            if (i >= padded.length) throw new IllegalArgumentException("Invalid padding");
        }
        i++;

        byte[] message = new byte[padded.length - i];
        System.arraycopy(padded, i, message, 0, message.length);
        return message;
    }

//    public static void main(String[] args) {
//        RSAPKCS1 rsa = new RSAPKCS1(1024, 5L);
//        String message = "Hello, RSA with PKCS#1!";
//        System.out.println("Original message: " + message);
//
//        BigInteger cipher = rsa.encrypt(message.getBytes());
//        System.out.println("Ciphertext: " + cipher.toString(16));
//
//        byte[] decrypted = rsa.decrypt(cipher);
//        System.out.println("Decrypted message: " + new String(decrypted));
//    }
}
