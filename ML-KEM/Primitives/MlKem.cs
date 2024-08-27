using System.Security.Cryptography;
using Waher.Security.SHA3;
using SHA3_256 = Waher.Security.SHA3.SHA3_256;
using SHA3_512 = Waher.Security.SHA3.SHA3_512;

namespace ML_KEM.Primitives;

public static class MlKem
{
    internal static (EncapsKey, DecapsKey) KeyGen_Internal(byte[] d, byte[] z, ParameterSet parameterSet)
    {
        (EncryptionKey ek, DecryptionKey dk) = Pke.KeyGen(d, parameterSet);
        byte[] h = new SHA3_256().ComputeVariable(ek.Serialize());
        
        return (new EncapsKey(ek), new DecapsKey(dk, ek, h, z, parameterSet));
    }
    
    /// <summary>
    /// Generates and encapsulation and decapsulation keypair using the specified parameter set
    /// </summary>
    /// <param name="parameterSet">Specifies the parameter set to use</param>
    /// <returns>(EncapsKey, DecapsKey)</returns>
    /// <exception cref="Exception">Throws an exception if the generated keys lead to any failed checks.</exception>
    public static (EncapsKey, DecapsKey) KeyGen(ParameterSet parameterSet)
    {
        RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] d = new byte[32];
        byte[] z = new byte[32];
        rng.GetBytes(d);
        rng.GetBytes(z);
        
        // Perform necessary checks before returning keys
        if (d.Length != 32 || z.Length != 32)
        {
            throw new Exception("Error getting random bytes.");
        }
        
        // Verify deterministic key generation
        (EncapsKey ekCandidate, DecapsKey dkCandidate) = KeyGen_Internal(d, z, parameterSet);
        (EncapsKey ekVerification, DecapsKey dkVerification) = KeyGen_Internal(d, z, parameterSet);
        if (!ekCandidate.Equals(ekVerification) || !dkCandidate.Equals(dkVerification))
        {
            throw new Exception("Failed to generate key pair, seed lead to non-deterministic keys.");
        }
        
        // Verify ek size
        byte[] serializedEk = ekCandidate.Serialize();
        if (serializedEk.Length != 384*parameterSet.k + 32)
            throw new Exception("Error generating key pair. Encapsulation key is the wrong length.");
        
        // Verify polynomial coefficients
        for (int i = 0; i < parameterSet.k; i++)
        {
            byte[] reEncoded = Polynomial.ByteDecode(serializedEk[(i * 384)..((i + 1) * 384)], 12).ByteEncode(12);
            if (!reEncoded.SequenceEqual(serializedEk[(i * 384)..((i + 1) * 384)]))
                throw new Exception("Public key contained invalid integer.");
        }
        
        
        // Verify decaps key length
        byte[] serializedDk = dkVerification.Serialize();
        if (serializedDk.Length != 768 * parameterSet.k + 96)
            throw new Exception("Error generating key pair. Decapsulation key is the wrong length.");
        
        // Verify the hash
        byte[] newHash = new SHA3_256().ComputeVariable(serializedDk[(384 * parameterSet.k)..(768 * parameterSet.k + 32)]);
        if (!newHash.SequenceEqual(serializedDk[(768 * parameterSet.k + 32)..(768 * parameterSet.k + 64)]))
            throw new Exception("Encaps key hash is incorrect.");
        
        // Pairwise consistency check
        (byte[] k, byte[] c) = ekCandidate.Encaps();
        byte[] kp = dkCandidate.Decaps(c);
        
        if (!k.SequenceEqual(kp))
            throw new Exception("Pairwise consistency check failed.");
        
        return (ekCandidate, dkCandidate);
    }
    
}

public class EncapsKey
{
    private readonly EncryptionKey _ek;

    internal EncapsKey(EncryptionKey ek)
    {
        _ek = ek;
    }
    
    /// <summary>
    /// Serializes the key to a byte array.
    /// </summary>
    /// <returns>byte array</returns>
    public byte[] Serialize()
    {
        return _ek.Serialize();
    }
    
    /// <summary>
    /// Deserializes the key
    /// </summary>
    /// <param name="data"></param>
    /// <param name="parameterSet"></param>
    /// <returns></returns>
    public static EncapsKey Deserialize(byte[] data, ParameterSet parameterSet)
    {
        return new EncapsKey(EncryptionKey.Deserialize(data, parameterSet));
    }

    internal (byte[], byte[]) Encaps_Internal(byte[] m)
    {
        byte[] ekHash = new SHA3_256().ComputeVariable(_ek.Serialize());
        byte[] seed = m.Concat(ekHash).ToArray();
        byte[] derivedKeyRandomness = new SHA3_512().ComputeVariable(seed);
        
        (byte[] K, byte[] r) = (derivedKeyRandomness[..32], derivedKeyRandomness[32..]);
        byte[] c = _ek.Encrypt(m, r);
        
        return (K, c);
    }

    /// <summary>
    /// Creates a shared secret key and ciphertext using the public key
    /// </summary>
    /// <returns>(K, c) where K is the shared secret, c should be distributed to the holder of the DecapsKey</returns>
    /// <exception cref="Exception">Throws an exception if there is an error generating random bytes.</exception>
    public (byte[], byte[]) Encaps()
    {
        RandomNumberGenerator rng = RandomNumberGenerator.Create();
        byte[] m = new byte[32];
        rng.GetBytes(m);
        
        if (m.Length != 32)
            throw new Exception("Error getting random bytes.");
        
        return Encaps_Internal(m);
    }

    public override bool Equals(object? obj)
    {
        if (obj == null || GetType() != obj.GetType())
            return false;
        EncapsKey encaps = obj as EncapsKey;
        
        return _ek.Equals(encaps._ek);
    }

    public override int GetHashCode()
    {
        int hash = 17;
        hash = hash * 17 + _ek.GetHashCode();
        return hash;
    }
}

public class DecapsKey
{
    private readonly DecryptionKey _dk;
    private readonly EncryptionKey _ek;
    private readonly byte[] _h;
    private readonly byte[] _z;
    private readonly ParameterSet _parameterSet;
    
    internal DecapsKey(DecryptionKey dk, EncryptionKey ek, byte[] h, byte[] z, ParameterSet parameterSet)
    {
        _dk = dk;
        _ek = ek;
        _h = h;
        _z = z;
        _parameterSet = parameterSet;
    }
    
    /// <summary>
    /// Serialized the key to a byte array.
    /// </summary>
    /// <returns></returns>
    public byte[] Serialize()
    {
        return _dk.Serialize().Concat(_ek.Serialize()).Concat(_h).Concat(_z).ToArray();
    }

    /// <summary>
    /// Deserializes the key from a byte array using the specified parameter set
    /// </summary>
    /// <param name="data"></param>
    /// <param name="parameterSet"></param>
    /// <returns></returns>
    public static DecapsKey Deserialize(byte[] data, ParameterSet parameterSet)
    {
        DecryptionKey dk = DecryptionKey.Deserialize(data[..(384 * parameterSet.k)], parameterSet);
        EncryptionKey ek = EncryptionKey.Deserialize(data[(384 * parameterSet.k)..(768 * parameterSet.k + 32)], parameterSet);
        byte[] h = data[(768 * parameterSet.k + 32)..(768 * parameterSet.k + 64)];
        byte[] z = data[(768 * parameterSet.k + 64)..(768 * parameterSet.k + 96)];
        
        return new DecapsKey(dk, ek, h, z, parameterSet);
    }

    internal byte[] Decaps_Internal(byte[] c)
    {
        byte[] mp = _dk.Decrypt(c);
        
        byte[] fullHash = new SHA3_512().ComputeVariable(mp.Concat(_h).ToArray());
        byte[] kp = fullHash[..32];
        byte[] rp = fullHash[32..];
        
        byte[] kBar = new SHAKE256(8 * 32).ComputeVariable(_z.Concat(c).ToArray());
        byte[] cPrime = _ek.Encrypt(mp, rp);

        if (!cPrime.SequenceEqual(c))
            return kBar;
        return kp;
    }
    
    /// <summary>
    /// Decapsulates the shared secret from the ciphertext using the DecapsKey.
    /// </summary>
    /// <param name="c">Ciphertext generated from encapsulation with the public key.</param>
    /// <returns>The shared secret K or garbage if something went wrong with encaps</returns>
    /// <exception cref="Exception"></exception>
    public byte[] Decaps(byte[] c)
    {
        if (c.Length != 32 * (_parameterSet.k * _parameterSet.du + _parameterSet.dv))
            throw new Exception("Invalid ciphertext length.");
        return Decaps_Internal(c);
    }

    public override bool Equals(object? obj)
    {
        if (obj == null || GetType() != obj.GetType())
            return false;
        
        DecapsKey decaps = obj as DecapsKey;
        return _dk.Equals(decaps._dk) && 
               _ek.Equals(decaps._ek) && 
               _h.SequenceEqual(decaps._h) && 
               _z.SequenceEqual(decaps._z) && 
               _parameterSet.Equals(decaps._parameterSet);
    }

    public override int GetHashCode()
    {
        int hash = 17;
        hash = 17 * hash + _ek.GetHashCode();
        hash = 17 * hash + _dk.GetHashCode();
        hash = 17 * hash + _h.GetHashCode();
        hash = 17 * hash + _z.GetHashCode();
        hash = 17 * hash + _parameterSet.GetHashCode();
        
        return hash;
    }
}