using Waher.Security.SHA3;

namespace ML_KEM.Primitives;

internal class NttPolynomial(short[] coeffs) : Polynomial(coeffs)
{
    /// <summary>
    /// Generates an NTTPolynomial based on the provided seed and indices
    /// </summary>
    /// <param name="seed">32 byte seed and two one byte indices concated. Total input size must be 34 bytes.</param>
    /// <returns></returns>
    public static NttPolynomial SampleNttPolynomial(Byte[] seed)
    {
        if (seed.Length != 34) throw new ArgumentException("Seed must be 34 bytes");
        // Add 33% more just in case any fail.
        // If a byte is larger than q we get another byte and 
        // in practice the byte is larger than q 19% of the time
        // so this should be more than enough of a buffer.
        var hash = new SHAKE128(3 * (256/2) * 8 * 3).ComputeVariable(seed);
        short[] outputCoeffs = new short[256];
        
        int j = 0;
        int hashIndex = 0;
        
        while (j < 256)
        {
            if (hashIndex >= hash.Length) throw new IndexOutOfRangeException("Hash length exceeded");
               
            short dOne = (short)(hash[hashIndex] + 256 * Utils.Mod(hash[hashIndex + 1], 16));
            short dTwo = (short)(Math.Floor((double)hash[hashIndex + 1] / 16) + 16 * hash[hashIndex + 2]);
            
            if (dOne < Parameters.Q)
            {
                outputCoeffs[j] = dOne;
                j++;
            }

            if (dTwo < Parameters.Q && j < 256)
            {
                outputCoeffs[j] = dTwo;
                j++;
            }
            hashIndex += 3;
        }
        return new NttPolynomial(outputCoeffs);
    }

    public Polynomial NttInverse()
    {
        short[] polyCoeffs = new short[256];
        Array.Copy(Coeffs, 0, polyCoeffs, 0, Coeffs.Length);
        int i = 127;

        for (int len = 2; len <= 128; len *= 2)
        {
            for (int start = 0; start < 256; start += 2 * len)
            {
                short zeta = Parameters.Zeta[i];
                i--;
                for (int j = start; j < start + len; j++)
                {
                    short t = polyCoeffs[j];
                    polyCoeffs[j] = Utils.ModQ(t + polyCoeffs[j + len]);
                    polyCoeffs[j + len] = Utils.ModQ(zeta * (polyCoeffs[j + len] - t));
                }
            }
        }

        for (int idx = 0; idx < 256; idx++)
        {
            short f = polyCoeffs[idx];
            polyCoeffs[idx] = Utils.ModQ(f * 3303);
        }
        
        return new Polynomial(polyCoeffs);
    }

    public override Polynomial Add(Polynomial rhs)
    {
        short[] output = new short[256];
        for (int i = 0; i < 256; i++)
        {
            output[i] = Utils.ModQ(Coeffs[i] + rhs.Coeffs[i]);
        }
        return new NttPolynomial(output);
    }
    
    public static NttPolynomial operator +(NttPolynomial lhs, NttPolynomial rhs)
    {
        return (NttPolynomial)lhs.Add(rhs);
    }

    public static NttPolynomial operator *(NttPolynomial lhs, NttPolynomial rhs)
    {
        short[] output = new short[256];
        for (int i = 0; i < 128; i++)
        {
            (short, short) h = BaseCaseMultiply(lhs.Coeffs[2*i], lhs.Coeffs[2*i + 1], rhs.Coeffs[2*i], rhs.Coeffs[2*i + 1], Parameters.ZetaPlusOne[i]);
            output[2 * i] = h.Item1;
            output[2 * i + 1] = h.Item2;
        }
        return new NttPolynomial(output);
    }
    
    /// NOTE: Params must be long otherwise the result will overflow and the result will be incorrect.
    private static (short, short) BaseCaseMultiply(long a0, long a1, long b0, long b1, long gamma)
    {
        short c0 = Utils.ModQ(a0 * b0 + a1 * b1 * gamma);
        short c1 = Utils.ModQ(a0 * b1 + a1 * b0);
        return (c0, c1);
    }
}

internal static class NttPolynomialExtensions {
    /// <summary>
    /// Computes the dot-product of the two vectors using the NttMultiply algorithm for each multiplication.
    /// </summary>
    /// <param name="lhs">k-length vector</param>
    /// <param name="rhs">k-length vector</param>
    /// <returns>`Scalar` polynomial resulting from the dot-product</returns>
    public static NttPolynomial NttDotProduct(this NttPolynomial[] lhs, NttPolynomial[] rhs)
    {
        NttPolynomial result = lhs[0] * rhs[0];
        for (int i = 1; i < lhs.Length; i++)
        {
            // Don't need to do this mod q as adding already does this
            result += lhs[i] * rhs[i];
        }
        
        return result;
    }
    
    /// <summary>
    /// Multiplies a k x k matrix and k-length vector with the matrix on the lhs.
    /// </summary>
    /// <param name="lhs">Square k x k matrix being multiplied</param>
    /// <param name="rhs">Vector of length k</param>
    /// <returns>Vector of length k</returns>
    public static NttPolynomial[] NttMVMultiply(this NttPolynomial[][] lhs, NttPolynomial[] rhs)
    {
        if (lhs.Length != rhs.Length && lhs[0].Length != rhs.Length)
            throw new ArgumentException("Arrays are not the same length");
        
        NttPolynomial[] result = new NttPolynomial[lhs.Length];
        for (int i = 0; i < lhs.Length; i++)
        {
            var row = lhs[i];
            result[i] = row[0] * rhs[0];
            for (int j = 1; j < lhs.Length; j++)
            {
                result[i] += row[j] * rhs[j];
            }
        }
        return result;
    }

    public static NttPolynomial[][] Transpose(this NttPolynomial[][] mat)
    {
        NttPolynomial[][] result = new NttPolynomial[mat.Length][];
        
        // Populate matrix with empty arrays
        for (int i = 0; i < mat.Length; i++)
        {
            result[i] = new NttPolynomial[mat.Length];
        }
        
        for (int i = 0; i < mat.Length; i++)
        {
            for (int j = 0; j < mat.Length; j++)
            {
                result[j][i] = mat[i][j];
            }
        }
        return result;
    }
    
    /// <summary>
    /// Adds two k-length vectors coordinate wise.
    /// </summary>
    /// <param name="lhs">k-length vector</param>
    /// <param name="rhs">k-length vector</param>
    /// <returns>Sum of the coordinate wise addition</returns>
    public static NttPolynomial[] NttVAdd(this NttPolynomial[] lhs, NttPolynomial[] rhs)
    {
        if (lhs.Length != rhs.Length) throw new ArgumentException("Arrays are not the same length");
        NttPolynomial[] output = new NttPolynomial[lhs.Length];
        
        for (int i = 0; i < lhs.Length; i++)
        {
            output[i] = lhs[i] + rhs[i];
        }
        
        return output;
    }

    public static Polynomial[] NttInverse(this NttPolynomial[] nttPoly)
    {
        Polynomial[] output = new Polynomial[nttPoly.Length];

        for (int i = 0; i < nttPoly.Length; i++)
        {
            output[i] = nttPoly[i].NttInverse();
        }
        
        return output;
    }
}