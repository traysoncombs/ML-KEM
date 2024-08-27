using ML_KEM.Primitives;
using Waher.Security.SHA3;

namespace ML_KEM;

internal static class Pke
{
    
    public static (EncryptionKey, DecryptionKey) KeyGen(byte[] seed, ParameterSet parameterSet)
    {
        // Concat k to the seed.
        byte[] seeds = new SHA3_512().ComputeVariable(seed.Append((byte)parameterSet.k).ToArray());
        byte[] rho = seeds[..32];
        byte[] sigma = seeds[32..];
        int N = 0;

        NttPolynomial[][] A = new NttPolynomial[parameterSet.k][];
        
        // Create coefficient matrix A
        for (int i = 0; i < parameterSet.k; i++)
        {
            A[i] = new NttPolynomial[parameterSet.k];
            for (int j = 0; j < parameterSet.k; j++)
            {
                // Seed is rho||j||i
                A[i][j] = NttPolynomial.SampleNttPolynomial(rho.Append((byte)j).Append((byte)i).ToArray());
            }
        }
        
        // Generate the secret key s
        Polynomial[] s = new Polynomial[parameterSet.k];
        for (int i = 0; i < parameterSet.k; i++)
        {
            byte[] tmpSeed = Utils.Prf(sigma, (byte)N, 8 * 64 * parameterSet.n1);
            s[i] = Polynomial.SamplePolyCbd(tmpSeed, parameterSet.n1);
            N++;
        }
        
        // Generate the error e
        Polynomial[] e = new Polynomial[parameterSet.k];
        for (int i = 0; i < parameterSet.k; i++)
        {
            byte[] tmpSeed = Utils.Prf(sigma, (byte)N, 8 * 64 * parameterSet.n1);
            e[i] = Polynomial.SamplePolyCbd(tmpSeed, parameterSet.n1);
            N++;
        }

        NttPolynomial[] sHat = s.Ntt();
        NttPolynomial[] eHat = e.Ntt();
        NttPolynomial[] tHat = A.NttMVMultiply(sHat).NttVAdd(eHat);
        
        return (new EncryptionKey(tHat, rho, parameterSet), new DecryptionKey(sHat, parameterSet));
    }
}

internal class EncryptionKey(NttPolynomial[] tHat, byte[] rho, ParameterSet parameterSet)
{
    protected NttPolynomial[] _tHat = tHat;
    protected byte[] _rho = rho;
    protected ParameterSet _parameterSet = parameterSet;
    
    public byte[] Serialize()
    {
        byte[] result = new byte[384 * parameterSet.k + 32];
        // Byte encode each polynomial and append to result
        for (int i = 0; i < tHat.Length; i++)
        {
            Array.Copy(tHat[i].ByteEncode(12), 0, result, i * 32 * 12, 32 * 12);
        }
        // Append rho to the end of the string
        Array.Copy(rho, 0, result, 32 * 12 * parameterSet.k, 32);
        
        return result;
    }

    public static EncryptionKey Deserialize(byte[] data, ParameterSet parameterSet)
    {
        byte[] tHatBytes = data[..(384 * parameterSet.k)];
        NttPolynomial[] tHat = new NttPolynomial[parameterSet.k];
        
        byte[] rho = data[(384 * parameterSet.k)..];
        for (int i = 0; i < parameterSet.k; i++)
        {
            tHat[i] = new NttPolynomial(Polynomial.ByteDecode(tHatBytes[(i * 32 * 12)..((i + 1) * 32 * 12)], 12).Coeffs);
        }
        
        return new EncryptionKey(tHat, rho, parameterSet);
    }

    public byte[] Encrypt(byte[] message, byte[] seed)
    {
        int N = 0;
        NttPolynomial[][] A = new NttPolynomial[parameterSet.k][];
        
        // Re-create coefficient matrix A from rho
        for (int i = 0; i < parameterSet.k; i++)
        {
            A[i] = new NttPolynomial[parameterSet.k];
            for (int j = 0; j < parameterSet.k; j++)
            {
                // Seed is rho||j||i
                A[i][j] = NttPolynomial.SampleNttPolynomial(rho.Append((byte)j).Append((byte)i).ToArray());
            }
        }
        
        Polynomial[] y = new Polynomial[parameterSet.k];
        for (int i = 0; i < parameterSet.k; i++)
        {
            byte[] tmpSeed = Utils.Prf(seed, (byte)N, 8 * 64 * parameterSet.n1);
            y[i] = Polynomial.SamplePolyCbd(tmpSeed, parameterSet.n1);
            N++;
        }
        
        Polynomial[] e1 = new Polynomial[parameterSet.k];
        for (int i = 0; i < parameterSet.k; i++)
        {
            byte[] tmpSeed = Utils.Prf(seed, (byte)N, 8 * 64 * parameterSet.n2);
            e1[i] = Polynomial.SamplePolyCbd(tmpSeed, parameterSet.n2);
            N++;
        }
        
        Polynomial e2 = Polynomial.SamplePolyCbd(Utils.Prf(seed,
                (byte)N,
                8 * 64 * parameterSet.n2),
            parameterSet.n2);
        
        NttPolynomial[] yHat = y.Ntt();
        Polynomial[] u = A.Transpose().NttMVMultiply(yHat).NttInverse().Add(e1);

        Polynomial mu = Polynomial.Deserialize(message, 1);
        Polynomial v = tHat.NttDotProduct(yHat).NttInverse() + e2 + mu;
        
        // Encode u into byte array
        byte[] c1 = new byte[32 * parameterSet.k * parameterSet.du];
        
        for (int i = 0; i < u.Length; i++)
        {
            byte[] tmp = u[i].Serialize(parameterSet.du);
            Array.Copy(tmp, 0, c1, i * tmp.Length, tmp.Length); // tmp.Length should be constant within function calls
        }
        
        byte[] c2 = v.Serialize(parameterSet.dv);
        return c1.Concat(c2).ToArray();
    }
    
    public override bool Equals(object? obj)
    {
        if (obj == null || GetType() != obj.GetType())
            return false;
        EncryptionKey ek = obj as EncryptionKey;
        
        return Enumerable.SequenceEqual(_tHat, ek._tHat) && 
               Enumerable.SequenceEqual(_rho, ek._rho) && 
               _parameterSet.Equals(ek._parameterSet);
    }

    public override int GetHashCode()
    {
        int hash = 17;
        hash = hash * 17 + parameterSet.GetHashCode();
        hash = hash * 17 + tHat.GetHashCode();
        hash = hash * 17 + rho.GetHashCode();
        return hash;
    }
}

internal class DecryptionKey(NttPolynomial[] sHat, ParameterSet parameterSet)
{
    protected NttPolynomial[] _sHat = sHat;
    protected ParameterSet _parameterSet = parameterSet;
    public byte[] Serialize()
    {
        byte[] result = new byte[384 * parameterSet.k];
        // Byte encode each polynomial and append to result
        for (int i = 0; i < sHat.Length; i++)
        {
            Array.Copy(sHat[i].ByteEncode(12), 0, result, i * 32 * 12, 32 * 12);
        }
        return result;
    }

    public static DecryptionKey Deserialize(byte[] data, ParameterSet parameterSet)
    {
        NttPolynomial[] sHat = new NttPolynomial[parameterSet.k];
        
        for (int i = 0; i < parameterSet.k; i++)
        {
            // Explicit conversion of Polynomial to Nttp is OK because the decoded polynomial is already in NTT
            sHat[i] = new NttPolynomial(Polynomial.ByteDecode(data[(i * 32 * 12)..((i + 1) * 32 * 12)], 12).Coeffs);
        }

        return new DecryptionKey(sHat, parameterSet);
    }

    public byte[] Decrypt(byte[] ciphertext) 
    {
        byte[] c1 = ciphertext[..(32 * parameterSet.k * parameterSet.du)];
        byte[] c2 = ciphertext[(32 * parameterSet.k * parameterSet.du)..(32*parameterSet.du*parameterSet.k + 32*parameterSet.dv)];

        Polynomial[] u = new Polynomial[parameterSet.k];
        
        for (int i = 0; i < parameterSet.k; i++)
        {
            Range r = new Range(i * 32 * parameterSet.du, (i + 1) * 32 * parameterSet.du);
            u[i] = Polynomial.Deserialize(c1[r], parameterSet.du);
        }
        
        Polynomial vp = Polynomial.Deserialize(c2, parameterSet.dv);

        Polynomial w = vp - sHat.NttDotProduct(u.Ntt()).NttInverse();
        
        return w.Serialize(1);
    }

    public override bool Equals(object? obj)
    {
        if (obj == null || GetType() != obj.GetType())
            return false;
        DecryptionKey dk = obj as DecryptionKey;
        return _parameterSet.Equals(dk._parameterSet) &&
               Enumerable.SequenceEqual(_sHat, dk._sHat);
    }

    public override int GetHashCode()
    {
        int hash = 17;
        hash = hash * 17 + parameterSet.GetHashCode();
        hash = hash * 17 + sHat.GetHashCode();
        return hash;
    }
}