using Microsoft.AspNetCore.Mvc.Filters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Web.Mvc.Filters;
using java.security;
using java.security.spec;
using System.IdentityModel.Tokens.Jwt;
using System.Web;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Crypto.Parameters;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json.Linq;

namespace JWTAuthen.AuthData
{
    public class AuthAttribute : IActionFilter
    {
        static string token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJodHRwczovL215aG9zdG5hbWUuY29ycC5pbnRyYW5ldC9UZXN0T25seUpXVCIsInZlciI6IjEuMCIsInJvbGUiOiJURVNUX09OTFkiLCJpc3MiOiJhcGlnYXRld2F5LW5vbnByb2QiLCJleHAiOjE1Njg2MzQ4NzYsImlhdCI6MTU2ODYyMDQ3NiwidXNlcmlkIjoiYWMzOTU2MyIsImp0aSI6IjIyYWE3YTQwLTg0MDUtNGE0Ny05M2RiLWYwOTA3NGQzYTcxZCIsIm1pc2MiOnsic3Zjbm0iOiIvQ3VzdG9tZXIvYWNjb3VudCIsImVudiI6IlRlc3QxIn19.Ce4VuXG4iGH2u1uWeWuaLzAy_12ZEjhSdEIWl8f1KGjzvcrxUBRjngPkiggShxgmqwgOJVNQoYIcarIRK__6Qg0_siLimkMw2JxC74JXnw5caiC8P6ijQGqSRpZQuWmNCGBVbO1eaRlZn8l08me_S4NVZBVCbj6LsKjCOHJHjXaWOKYxt4u-aFjW7fQ37Y1Ym7T7vw5RkllJ8gWGj5copmAE8qMsA00j6NMes8eAzKdbprNDmHkdnG6MZFkAcM8VQhdC7mVGKMoJ6KUfiEA_t0FKKNYP5FNV2YJM_GOPe20UD-GxC_DDpvnhOzQhbQp2_0n4-TFOIC0XvY-uMJNaFxVvNuGujeJ7XiadoQq0P_jhUhLfqVAvIwH01ArkEWh5Ztb5xbypt-K8zXuOgCwqoaeJ3hXTTehwRE08E0HWELRJvAUTvIOJ0Y4IdSfWDneOwHAgBVvlR-TGfZ4RGAMttvma19yP7-TAllgksyj-OasxYbrvy084SzMDxBGqnQTabsyZG9FQe7VChHFOVLWc0W97uCj_TsWsTbuqFRJbuRgBlSY_fWyN_7MrOaKTS0G66psvJ11J986M80HsPoC3QqZ__vTLgvpS6_ZcCgUEzF3R5H-MDsOn0dUN4Ax53N6RH1cQO9R4Gx65u_EDzXedM0GNFGPEUbyAh19ufsJ_bgw";
        static string KEYFACTORY = "RSA";
        static string JWT_TYPE = "JWT";
        static string JWT_ALGORITHM = "RS256";
        static string publickey = "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAzWKPMwumwUso/sQLwAUyj3c040SPwaRhNcFN5dmjl5NOG3XizxPXD3E20CLeMCQ6mdsO6wrKfQVS0nGaYim9PNWiYteJd5cZk6faxLq9T7W6JUupTqqEajHMkbkWusp5o3zDMgXL0I8CBWHGs8ymQvdheTi1QiaSaGwAYZO2KJJGgtaRVwRcU9t5PghBqiEy/keqm2sK/ypykdHY5SbNHw/pcZOGYYIVEZNwePEMlA/kpv6tNJPHg4hIkam+EREV947QOfYCWf0lPRi/JmEmoPFsdFBXW/QTyDTnLNujChmlp63Yp7IXgXfV3ENZ65FszqdTvrg5SnUql3Ctceq5wrIQfkqvVJ2poogk/8jR24pbzkKNeUVYWDem0nIVlfHMI3e66D+EQctgDaivOaw4LR1/j3Um25mcyM+fsrWE+ugD8YlTEnm7i2jxdFlOZ63S2hIcioLBwpfvotlj61LikTecn+QojjKRnaeMBa22RrLkvBxtGNbtM8tDID+OWBkoa4f0q0Uz1s55Bc4CW7FKGXprDylfimzvo+ZMuG4M39nmJWZrRP7YBDLc6+6JWnv7EsJ+4fhocaajXBlKjvTYJUaOP22uGBMvaZlbqv6K1wVyz5p81bJkL7d4eBUxCI1NaUe12M3rLe8gZzJsu2EJYZC3lRHgNs/2uLL6WErn6KECAwEAAQ==";
        static string iss = "apigateway-nonprod";
        string sub = "hyperion";
        static string issuerURL = "https://myhostname.corp.intranet/TestOnlyJWT";

        public void OnActionExecuted(ActionExecutedContext context)
        {
           // throw new NotImplementedException();
        }

        public void OnActionExecuting(ActionExecutingContext context)
        {

            // configure jwt authentication
            //var key = Encoding.ASCII.GetBytes(publickey);
             byte[] key = null;



            // byte[] publicBytes = Convert.FromBase64String(publickey);// Base64.getDecoder().decode(publickey.getBytes());
            // byte[] bytes = Encoding.ASCII.GetBytes(publickey);
            byte[] textAsBytes = System.Convert.FromBase64String(publickey);
            String headers = token;//context.HttpContext.Request.Headers["Authorization"];
            string[] parts = headers.Split('.');
            string header = parts[0];
            string payload = parts[1];
            String jwtToken = header.Substring(7);

            string headerJson = Encoding.UTF8.GetString(Base64UrlDecode(header));
            JObject headerData = JObject.Parse(headerJson);

            string payloadJson = Encoding.UTF8.GetString(Base64UrlDecode(payload));
            JObject payloadData = JObject.Parse(payloadJson);
            AsymmetricKeyParameter asymmetricKeyParameter = PublicKeyFactory.CreateKey(textAsBytes);
            RsaKeyParameters rsaKeyParameters = (RsaKeyParameters)asymmetricKeyParameter;
            RSAParameters rsaParameters = new RSAParameters();
            rsaParameters.Modulus = rsaKeyParameters.Modulus.ToByteArrayUnsigned();
            rsaParameters.Exponent = rsaKeyParameters.Exponent.ToByteArrayUnsigned();
            RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
            rsa.ImportParameters(rsaParameters);

            SHA256 sha256 = SHA256.Create();
            byte[] hash = sha256.ComputeHash(Encoding.UTF8.GetBytes(parts[0] + '.' + parts[1]));

            RSAPKCS1SignatureDeformatter rsaDeformatter = new RSAPKCS1SignatureDeformatter(rsa);
            rsaDeformatter.SetHashAlgorithm("RS256");
            if (!rsaDeformatter.VerifySignature(hash, FromBase64Url(parts[2])))
                throw new ApplicationException(string.Format("Invalid signature"));      
            //Check for header and payload 
             Validate(headerData, payloadData);
        }

        private bool Validate(JObject headerData, JObject payloadData)
        {
            if (headerData["typ"].ToString() != "JWT" && headerData["alg"].ToString() != "RS256")
            {
                throw new Exception("Invalid JWT Type or Algorithm");
            }
            if (payloadData["sub"].ToString() != issuerURL && payloadData["iss"].ToString() != iss)
            {
                throw new Exception("Invalid JWT Sub or Issuer");
            }
            return true;
        }
          
        static byte[] FromBase64Url(string base64Url)
        {
            string padded = base64Url.Length % 4 == 0
                ? base64Url : base64Url + "====".Substring(base64Url.Length % 4);
            string base64 = padded.Replace("_", "/")
                .Replace("-", "+");
            return Convert.FromBase64String(base64);
        }

        // from JWT spec
        private  byte[] Base64UrlDecode(string input)
        {
            var output = input;
            output = output.Replace('-', '+'); // 62nd char of encoding
            output = output.Replace('_', '/'); // 63rd char of encoding
            switch (output.Length % 4) // Pad with trailing '='s
            {
                case 0: break; // No pad chars in this case
                case 1: output += "==="; break; // Three pad chars
                case 2: output += "=="; break; // Two pad chars
                case 3: output += "="; break; // One pad char
                default: throw new System.Exception("Illegal base64url string!");
            }
            var converted = Convert.FromBase64String(output); // Standard base64 decoder
            return converted;
        }

    }
    }

