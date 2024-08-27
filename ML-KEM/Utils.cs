using System.Collections;
using Waher.Security.SHA3;

namespace ML_KEM;

internal class Utils
{
    private const int q = 3329;
    private const int n = 256;
    private const int z = 17;
    
    public static byte[] BitsToBytes(BitArray bits)
    {
        byte[] bytes = new byte[bits.Length / 8];
        // Zero out array
        Array.Clear(bytes);
        
        for (int i = 0; i < bits.Length; i++)
        {
            int byteIndex = (int)Math.Floor((float)(i / 8));
            bytes[byteIndex] += Convert.ToByte((bits[i] ? 1 : 0) << (i % 8));
        }
        return bytes;
    }

    public static BitArray BytesToBits(byte[] bytes)
    {
        return new BitArray(bytes);
    }

    public static short Compress(short value, int d)
    {
        return (short)Mod((int)Math.Round(value * ((decimal)(1 << d) / q), MidpointRounding.AwayFromZero), 1 << d);
    }
    
    public static short[] Compress(short[] values, int d)
    {
        short[] result = new short[values.Length];
        for (int i = 0; i < values.Length; i++)
        {
            result[i] = Compress(values[i], d);
        }
        return result;
    }
    
    public static short Decompress(short value, int d)
    {
        return (short) Math.Round(value * (q / (decimal) (1 << d)), MidpointRounding.AwayFromZero);
    }
    
    public static short[] Decompress(short[] values, int d)
    {
        short[] result = new short[values.Length];
        for (int i = 0; i < values.Length; i++)
        {
            result[i] = Decompress(values[i], d);
        }
        return result;
    }
    
    public static int Mod(int x, int m) {
        int r = x % m;
        return r < 0 ? r + m : r;
    }

    public static short ModQ(int x)
    {
        return (short) Mod(x, Parameters.Q);
    }
    
    public static short ModQ(long x)
    {
        long r = x % Parameters.Q;
        return (short)(r < 0 ? r + Parameters.Q : r);
    }

    public static byte[] Prf(byte[] s, byte b, int bitSize)
    {
        return new SHAKE256(bitSize).ComputeVariable(s.Append(b).ToArray());
    }
    
    public static byte[] Prf(byte[] s, byte[] b, int bitSize)
    {
        return new SHAKE256(bitSize).ComputeVariable(s.Concat(b).ToArray());
    }
}