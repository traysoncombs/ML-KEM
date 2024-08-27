using System.Collections;
using System.Text;
using ML_KEM;

namespace ML_KEM_Test;

[TestClass]
public class UtilsTest
{
    [TestMethod]
    public void BitsToBytesTest()
    {
        byte[][] cases = [
            [0xA0, 0xAD, 0xFF, 0xAF, 0x11],
            [0xA1],
            [0x00, 0x00, 0x00]
        ];
        
        foreach (var c in cases)
        {
            CollectionAssert.AreEqual(c, Utils.BitsToBytes(new BitArray(c)));
        }
    }

    [TestMethod]
    public void BytesToBitsTest()
    {
        var caseOne = new Byte[] {0xA0};
        var expectedOne = new BitArray(new Byte[] { 0xA0 });
        var actualOne = Utils.BytesToBits(caseOne);

        CollectionAssert.AreEqual(expectedOne, actualOne);
    }

    [TestMethod]
    public void BytesToBitsReversibilityTest()
    {
        Random rnd = new Random();
        
        byte[] og = new byte[256];
        rnd.NextBytes(og);
        
        BitArray transformed = Utils.BytesToBits(og);
        byte[] result = Utils.BitsToBytes(transformed);
        
        CollectionAssert.AreEqual(result, og);
    }

    [TestMethod]
    public void CompressionReversibilityTest()
    {
        for (short i = 1; i <= 1 << 11; i <<= 1)
        {
            for (short d = 1; d < 12; d++)
            {
                if (i < (1 << d))
                {
                    Assert.AreEqual(i, Utils.Compress(Utils.Decompress(i, d), d));
                }
            }
            
        }
    }
}