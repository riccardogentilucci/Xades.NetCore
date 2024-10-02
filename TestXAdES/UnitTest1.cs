using FirmaXadesNet;
using FirmaXadesNet.Crypto;
using FirmaXadesNet.Signature.Parameters;
using System.Security.Cryptography.X509Certificates;

namespace TestXAdES {
    [TestClass]
    public class UnitTest1 {
        [TestMethod]
        public void TestMethod1() {
            var xadesService = new XadesService();
            var parametri = new SignatureParameters();
            parametri.SignatureMethod = SignatureMethod.ECDSAwithSHA256;
            parametri.SignaturePackaging = SignaturePackaging.ENVELOPED;
            parametri.SigningDate = DateTime.Now;
            parametri.Signer = new Signer(new X509Certificate2(@"..\..\..\test.p12", "1234"));
               
            using (var fs = new FileStream(@"..\..\..\test.xml", FileMode.Open)) {
                var signedDocument = xadesService.Sign(fs, parametri);
                File.WriteAllText(@"..\..\..\test-output.xml", signedDocument.Document.OuterXml); 
            }
        }
    }
}