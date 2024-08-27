using System.Collections;
using ML_KEM.Primitives;

namespace ML_KEM;

internal class Polynomial
{
    public short[] Coeffs { get; set; }

    public Polynomial(short[] coeffs)
    {
        if (coeffs.Length != 256) throw new ArgumentException("Must contain 256 coefficients");
        Coeffs = coeffs;
    }
    
    // Encodes coeffs as d-bit integers into a byte array.
    // Each integer must be representable in `d` bits; that is coeff < 2^d, errors otherwise
    public byte[] ByteEncode(int d)
    {
        int m = d == 12 ? Parameters.Q : 1 << d;
        BitArray b = new BitArray(32 * d * 8);
        
        // Convert each integer into `d` bits
        for (int i = 0; i < 256; i++)
        {
            short a = Coeffs[i];
            
            if (a > m) throw new ArithmeticException("Coefficient cant be represented in d-bits");
            
            for (int j = 0; j < d; j++)
            {
                short val = (short) Utils.Mod(a, 2);
                
                b[i * d + j] = val == 1;
                a = (short)((a - val) / 2);
            }
        }
        return Utils.BitsToBytes(b);
    }
    
    // Does the reverse of ByteEncode
    public static Polynomial ByteDecode(byte[] coeffs, int d)
    {
        BitArray bits = Utils.BytesToBits(coeffs);
        short[] data = new short[256];
        int m = d == 12 ? Parameters.Q : 1 << d;
        
        // Create each integer from the respective `d` bits
        for (int i = 0; i < 256; i++)
        {
            for (int j = 0; j < d; j++)
            {
                int val = bits[i * d + j] ? 1 : 0;
                data[i] += (short) Utils.Mod(val * (1 << j), m);
            }
        }
        
        return new Polynomial(data);
    }

    public static Polynomial Deserialize(byte[] data, int d)
    {
        Polynomial output = ByteDecode(data, d);
        short[] decompressed = Utils.Decompress(output.Coeffs, d);
        output.Coeffs = decompressed;
        return output;
    }

    public byte[] Serialize(int d)
    {
        return new Polynomial(Utils.Compress(Coeffs, d)).ByteEncode(d);
    }

    public static Polynomial SamplePolyCbd(byte[] seed, int n)
    {
        short[] f = new short[256];
        BitArray bits = Utils.BytesToBits(seed);
        for (int i = 0; i < 256; i++)
        {
            int x = 0;
            int y = 0;
            for (int j = 0; j < n; j++)
                x += bits[2 * i * n + j] ? 1 : 0;
            for (int j = 0; j < n; j++)
                y += bits[2 * i * n + n + j] ? 1 : 0;
            f[i] = Utils.ModQ(x - y);
        }

        return new Polynomial(f);
    }

    public virtual Polynomial Add(Polynomial rhs)
    {
        short[] output = new short[256];
        for (int i = 0; i < 256; i++)
        {
            output[i] = Utils.ModQ(this.Coeffs[i] + rhs.Coeffs[i]);
        }
        return new Polynomial(output);
    }
    
    public static Polynomial operator +(Polynomial lhs, Polynomial rhs)
    {
        return lhs.Add(rhs);
    }

    public static Polynomial operator -(Polynomial lhs, Polynomial rhs)
    {
        short[] output = new short[256];
        for (int i = 0; i < 256; i++)
        {
            output[i] = Utils.ModQ(lhs.Coeffs[i] - rhs.Coeffs[i]);
        }
        
        return new Polynomial(output);
    }

    public NttPolynomial Ntt()
    {
        short[] nttPolynomialCoeffs = new short[256];
        Array.Copy(Coeffs, 0, nttPolynomialCoeffs, 0, Coeffs.Length);
        int i = 1;

        for (int len = 128; len >= 2; len = len / 2)
        {
            for (int start = 0; start < 256; start += 2 * len)
            {
                short zeta = Parameters.Zeta[i];
                i++;
                for (int j = start; j < start + len; j++)
                {
                    short t = Utils.ModQ(zeta * nttPolynomialCoeffs[j + len]);
                    nttPolynomialCoeffs[j + len] = Utils.ModQ(nttPolynomialCoeffs[j] - t);
                    nttPolynomialCoeffs[j] = Utils.ModQ(nttPolynomialCoeffs[j] + t);
                }
            }
        }
        return new NttPolynomial(nttPolynomialCoeffs);
    }

    public override bool Equals(object? obj)
    {
        if (obj == null || GetType() != obj.GetType())
            return false;
        
        Polynomial poly = obj as Polynomial;

        return Enumerable.SequenceEqual(Coeffs, poly.Coeffs);
    }

    public override int GetHashCode()
    {
        return Coeffs.GetHashCode();
    }
}

internal static class PolynomialExtensions
{
    public static NttPolynomial[] Ntt(this Polynomial[] poly)
    {
        NttPolynomial[] result = new NttPolynomial[poly.Length];
        for (int i = 0; i < poly.Length; i++)
        {
            result[i] = poly[i].Ntt();
        }
        return result;
    }

    public static Polynomial[] Add(this Polynomial[] lhs, Polynomial[] rhs)
    {
        if (lhs.Length != rhs.Length) throw new ArgumentException("Polynomial vectors must have the same length");
        
        Polynomial[] output = new Polynomial[lhs.Length];
        
        for (int i = 0; i < lhs.Length; i++)
        {
            output[i] = lhs[i] + rhs[i];
        }
        
        return output;
    }
}