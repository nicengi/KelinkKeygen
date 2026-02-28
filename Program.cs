using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace KelinkKeygen
{
    internal class Program
    {
        // 原版许可证，用于测试
        // 许可证域名为 wi0.cccn-10086.com 但实际签名域名为 wi0.cc，获取机器码时要单独处理
        static string regcodeTest = "n9FZc/xMKOxg6+2ZLixJjr4mlgGK+7jio8ABuv4KQ2P8HjpJDXeJY49FICIaaOPfbZkSjfDfB7TXIlrJXCeYBrC7e1VoFf2gg7uY78A8F4YNA0WbA5yHvDVEBxaD5YDAGww82SVKzTXna8YhtsShGrblkY/H/FytZ2yCSJKwK/4=d+kcmOBwUpZCFhwGCVrP9ewsbR/ANms3r618FMoyKT1IIroDK5Pin+544MXivK8Q8ndzt6Mv27c63tELkNCo+TclUiY9FAGdp7K8AMJDgjhGWLwQx1DpQkPBYrD3PPx837zNehSwOJU=";

        static void Main(string[] args)
        {
            /*
             * KL_VERSION
             * 0:企业版
             * 1:标准版
             * 2:个人版
             * 3:DIY版
             * 4:开发版
             * 5:源码版
             */
            string newRegcode = LicenseTool.GenerateRegcode("20001", "5", "0", "192.168.0.10");
            Console.WriteLine($"New Regcode: \n{newRegcode}");
            Console.WriteLine();
            Console.WriteLine();

            Console.WriteLine("=================================================================");
            Console.WriteLine("License Info:");

            string regCode = newRegcode;// 要解析的许可证
            //regCode = regcodeTest;

            string stremp = LicenseTool.DesDecrypt(LicenseTool.GetFunction(regCode)).ToLower();
            Console.WriteLine(stremp);
            Console.WriteLine();
            string LIC_ID = LicenseTool.GetSiteDefault(stremp, 0);
            string LIC_DOMAIN = LicenseTool.GetSiteDefault(stremp, 3);
            string KL_VERSION = LicenseTool.getArryString(stremp, '|', 1);
            string KL_VERSION_STR = LicenseTool.GetSystemVersion(KL_VERSION, "0");
            string KL_SITEID = LicenseTool.getArryString(stremp, '|', 2);
            string MACHINE_CODE = LicenseTool.GetMachineCode(LIC_DOMAIN);

            if (LIC_DOMAIN == "wi0.cccn-10086.com")
            {
                MACHINE_CODE = LicenseTool.GetMachineCode("wi0.cc");
            }

            Console.WriteLine($"LICENSE_ID: {LIC_ID}");
            Console.WriteLine($"LICENSE_DOMAIN: {LIC_DOMAIN}");
            Console.WriteLine($"KL_VERSION: {KL_VERSION} ({KL_VERSION_STR})");
            Console.WriteLine($"KL_SITEID: {KL_SITEID}");
            Console.WriteLine($"MACHINE_CODE: {MACHINE_CODE}");
            bool isReg = LicenseTool.VerifySignature(MACHINE_CODE, regCode);
            Console.WriteLine($"O_Signatured: {isReg}"); // 使用原公钥验证签名
            Console.WriteLine("=================================================================");

            bool isRegKeygen = LicenseTool.VerifySignatureKeygen(MACHINE_CODE, regCode);
            Console.WriteLine($"K_Signatured: {isRegKeygen}"); // 使用替换的公钥验证签名


            //NewRSA();
            Console.ReadKey();
        }


        static void NewRSA()
        {
            using (RSACryptoServiceProvider rsa = new RSACryptoServiceProvider(1024)) // 和原长度一致
            {
                string publicKey = rsa.ToXmlString(false);  // 公钥
                string privateKey = rsa.ToXmlString(true);  // 私钥

                Console.WriteLine("公钥：");
                Console.WriteLine(publicKey);

                Console.WriteLine("\n私钥：");
                Console.WriteLine(privateKey);
            }
        }
    }
}
