using System.Collections;
using ML_KEM;
using ML_KEM.Primitives;

namespace ML_KEM_Test;

[TestClass]
public class PolynomialTest
{
    [TestMethod]
    public void ByteEncodingTest()
    {
        int d = 4;
        // Fill data with 0's
        short[] data = Enumerable.Repeat((short) 0, 256).ToArray();
        // Copy our test data in
        Array.Copy((short[]) [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], data, 16);
        
        byte[] expectedOne = Enumerable.Repeat((byte) 0, 32 * d).ToArray();
        Array.Copy((byte[]) [0x10, 0x32, 0x54, 0x76, 0x98, 0xBA, 0xDC, 0xFE], expectedOne, 8);
        
        Polynomial testcaseOne = new Polynomial(data);
        
        var actualOne = testcaseOne.ByteEncode(d);
        
        CollectionAssert.AreEqual(expectedOne, actualOne);

    }
    
    [TestMethod]
    public void ByteEncodingInvertibilityTest()
    {
        for (int d = 1; d <= 8; d++)
        {
            short[] data = GenRndCoeffs(d);

            Polynomial testCaseOne = new Polynomial(data);

            var actualOne = Polynomial.ByteDecode(testCaseOne.ByteEncode(d), d);
            
            CollectionAssert.AreEqual(data, actualOne.Coeffs);
        }
    }

    [TestMethod]
    public void NttPolynomialTest()
    {
        // We will assume this is uniform
        Random rnd = new Random();
        byte[] data = new byte[34];
        rnd.NextBytes(data);
        NttPolynomial poly = NttPolynomial.SampleNttPolynomial(data);
    }
    
    [TestMethod]
    public void SamplePolyCbdTest()
    {
        int n = 2;
        Random rnd = new Random();
        byte[] data = new byte[64 * n];
        rnd.NextBytes(data);
        Polynomial poly = Polynomial.SamplePolyCbd(data, n);
        
        n = 3;
        data = new byte[64 * n];
        rnd.NextBytes(data);
        poly = Polynomial.SamplePolyCbd(data, n);
    }

    [TestMethod]
    public void NttReveribilityTest()
    {
        // Test poly -> ntt -> poly
        Polynomial og = new Polynomial(GenRndCoeffs(11));
        NttPolynomial transformed = og.Ntt();
        Polynomial result = transformed.NttInverse();
        
        CollectionAssert.AreEqual(og.Coeffs, result.Coeffs);
        
        // Test ntt -> poly -> ntt
        Random rnd = new Random();
        byte[] seed = new byte[34];
        rnd.NextBytes(seed);
        NttPolynomial ogTwo = NttPolynomial.SampleNttPolynomial(seed);
        Polynomial transformedTwo = ogTwo.NttInverse();
        NttPolynomial resultTwo = transformedTwo.Ntt();
        
        CollectionAssert.AreEqual(ogTwo.Coeffs, resultTwo.Coeffs);
    }
    
    // Generate coeffs up to `d` bits
    public short[] GenRndCoeffs(int d)
    {
        Random rnd = new Random();
        short[] data = new short[256];
        
        for (int i = 0; i < 256; i++)
        {
            data[i] = (short)rnd.Next(0, 1 << d);
        }

        return data;
    }
    
    public short[] GenRndCoeffsUpToAndExcludingQ()
    {
        Random rnd = new Random();
        short[] data = new short[256];
        
        for (int i = 0; i < 256; i++)
        {
            data[i] = (short)rnd.Next(0, Parameters.Q);
        }

        return data;
    }
}