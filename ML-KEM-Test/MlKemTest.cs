using System.Text.Json;
using System.Text.Json.Serialization;
using ML_KEM;
using ML_KEM.Primitives;

namespace ML_KEM_Test;

[TestClass]
public class MlKemTest
{
    private static ParameterSet[] ParameterSets = [Parameters.ML_KEM_512, Parameters.ML_KEM_768, Parameters.ML_KEM_1024];
    
    [TestMethod]
    public void KemBruteForceTest()
    {
        foreach (ParameterSet p in ParameterSets)
        {
            for (int i = 0; i < 1000; i++)
            {
                // All the checks are done in keygen so we don't have to do too much here.
                (EncapsKey ek, DecapsKey dk) = MlKem.KeyGen(p);
            }
            
        }
    }

    [TestMethod]
    public void KemSerializationTest()
    {
        foreach (ParameterSet p in ParameterSets)
        {
            (EncapsKey ek, DecapsKey dk) = MlKem.KeyGen(p);
            byte[] ekBytes = ek.Serialize();
            byte[] dkBytes = dk.Serialize();
            
            Assert.AreEqual(ek, EncapsKey.Deserialize(ekBytes, p));
            Assert.AreEqual(dk, DecapsKey.Deserialize(dkBytes, p));
        }
    }

    [TestMethod]
    public void KemFidelityTest()
    {
        String data = File.ReadAllText(@"..\..\..\testcases.json");
        TestCase[][] testData = JsonSerializer.Deserialize<TestCase[][]>(data) ?? throw new Exception("Error deserializing test data");
        for (int i = 0; i < 3; i++)
        {
            ParameterSet p = ParameterSets[i];
            TestCase[] testCases = testData[i];
            foreach (TestCase testCase in testCases)
            {
                byte[] d = Convert.FromHexString(testCase.D);
                byte[] z = Convert.FromHexString(testCase.Z);
                byte[] m = Convert.FromHexString(testCase.M);
                byte[] ek = Convert.FromHexString(testCase.Ek);
                byte[] dk = Convert.FromHexString(testCase.Dk);
                byte[] c = Convert.FromHexString(testCase.C);
                byte[] kPrime = Convert.FromHexString(testCase.KPrime);
                byte[] k = Convert.FromHexString(testCase.K);
                
                (EncapsKey ekResult, DecapsKey dkResult) = MlKem.KeyGen_Internal(d, z, p);
                (byte[] kResult, byte[] cResult) = ekResult.Encaps_Internal(m);
                byte[] kPrimeResult = dkResult.Decaps_Internal(cResult);
                
                CollectionAssert.AreEqual(ek, ekResult.Serialize());
                CollectionAssert.AreEqual(dk, dkResult.Serialize());
                CollectionAssert.AreEqual(k, kResult);
                CollectionAssert.AreEqual(c, cResult);
                CollectionAssert.AreEqual(kPrime, kPrimeResult);
            }
        }
        
    }

    public struct TestCase
    {
        [JsonPropertyName("d")]
        public string D { get; set; }

        [JsonPropertyName("z")] 
        public string Z { get; set; }

        [JsonPropertyName("m")] 
        public string M { get; set; }

        [JsonPropertyName("ek")] 
        public string Ek { get; set; }
        
        [JsonPropertyName("dk")] 
        public string Dk { get; set; }
        
        [JsonPropertyName("k")] 
        public string K { get; set; }
        
        [JsonPropertyName("c")] 
        public string C { get; set; }
        
        [JsonPropertyName("k_prime")] 
        public string KPrime { get; set; }
    }
    
}