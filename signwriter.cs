// Inject data into a signed executable by adding a custom cert

using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Linq;
using System.Security.Cryptography;
using IOFile = System.IO.File;

public class SignWriter {

    // Hardcoding stuff is fun, you should try it
    public const string signOid = "1.3.6.1.4.1.38136.31337";
    public const string signSubject = "CN=Certone";

    public static int Main(string[] args) {

        string codeBase = AppContext.BaseDirectory + System.AppDomain.CurrentDomain.FriendlyName;
        if (args.Length < 2) {
            System.Console.WriteLine($"Need three arguments: \n {codeBase} <target installer> <data>\n <data> will be injected into {signSubject} cert with oid {signOid}");
            return 1;
        }

        var data = String.Join(" ", args.Skip(1).ToArray()); // combine all elements, skipping first one
        var targetFile = args[0];
        if (!File.Exists(targetFile)) {
            Console.WriteLine($"Can't find the file '{targetFile}'");
            return 2;
        }
        // first check if we're targeting windows or linux executable.
        if (isELF(targetFile)) {
            if (isDataInsideElf(targetFile)) {
                Console.WriteLine($"The file '{targetFile}' had data already embedded");
                return 0;
            }
            InjectDataIntoElf(targetFile, data);
            return 0;
        }
        string signTool;
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux)) {
            signTool = AppContext.BaseDirectory + "osslsigncode";  // get and complile from https://github.com/mtrojnar/osslsigncode. The one from apt osslsigncode package has external dependencies
            ExtractResource("sign.osslsigncode", signTool);
            using (Process proc = Process.Start("/bin/bash", $"-c \"chmod 700 '{signTool}'\"")) {
                proc.WaitForExit();
            }
            // or you can 
            // var unixFileInfo = new Mono.Unix.UnixFileInfo(systemScanner);
            // unixFileInfo.FileAccessPermissions = Mono.Unix.FileAccessPermissions.UserExecute | Mono.Unix.FileAccessPermissions.UserRead | Mono.Unix.FileAccessPermissions.UserWrite;
        } else {
            signTool = AppContext.BaseDirectory + "signtool.exe";
            ExtractResource("sign.signtool", signTool);
            Console.WriteLine("Sorry this codepath is not implemented");
            return 254;
        }
        try {
            SignFile(targetFile, signTool, signSubject, signOid, data);
            try { IOFile.Delete(signTool); } catch { }
            Console.WriteLine("Success");
        } catch (Exception ex) {
            Console.WriteLine(ex.ToString() + ":" + ex.Message);
            return 2;
        }
        return 0;
    }

    private static bool isELF(string targetFile) {
        byte[] magic = { 0x7F, 0x45, 0x4C, 0x46 };
        using (FileStream fs = new FileStream(targetFile, FileMode.Open, FileAccess.Read)) {
            foreach (int i in magic) {
                if (i != fs.ReadByte())
                    return false;
            }
        }
        return true;
    }

    public static void InjectDataIntoElf(string targetFile, string data) {
        var bytedata = Encoding.UTF8.GetBytes(data);
        // create an array that starts with the data provided
        // var bytesegment = Enumerable.Repeat((byte)0, 768).ToArray(); // empty array
        byte[] bytesegment = new byte[992];
        // for (var i = 0; i < bytedata.Length && i<768; i++)
        //     bytesegment[i] = bytedata[i];
        Array.Copy(bytedata, 0, bytesegment, 0, bytedata.Length);

        // Output name from hashed data
        var hasher = new SHA256Managed();
        var hash64 = System.Convert.ToBase64String(hasher.ComputeHash(Encoding.UTF8.GetBytes(data))).Replace('+', '-').Replace('/', '_'); // url safe, which also happens to be filesystem safe
        var outFile = Path.GetFileNameWithoutExtension(targetFile) + "-" + hash64.Substring(0, 8);

        var datahash = (new SHA256Managed()).ComputeHash(bytesegment);
        // append hash to data
        byte[] datafileblock = new byte[1024]; // bytesegment.Length + datahash.Length]; 
        Array.Copy(bytesegment, 0, datafileblock, 0, bytesegment.Length);
        Array.Copy(datahash, 0, datafileblock, bytesegment.Length, datahash.Length);

        try { IOFile.Delete(outFile); } catch { }
        // write to file
        FileStream fsDst = new FileStream(outFile, FileMode.Create, FileAccess.Write);
        FileStream fsSrc = new FileStream(targetFile, FileMode.Open, FileAccess.Read);
        fsSrc.CopyTo(fsDst);
        BinaryWriter writer = new BinaryWriter(fsDst);
        writer.Write(datafileblock);

        fsSrc.Close();
        fsDst.Close();
        fsSrc.Dispose();
        fsDst.Dispose();
    }

    public static bool isDataInsideElf(string targetFile) {
        // read and check the last KB
        FileStream fsSrc = new FileStream(targetFile, FileMode.Open, FileAccess.Read);
        BinaryReader reader = new BinaryReader(fsSrc);
        byte[] filedata = new byte[1024];
        //  (Int32)((new FileInfo(targetFile)).Length) - 1024
        fsSrc.Seek(-1024, SeekOrigin.End);
        if (reader.Read(filedata, 0, 1024) != 1024) {
            throw new Exception("Cant read file to check");
        }

        byte[] bytesegment = new byte[992];
        // for (var i = 0; i < bytedata.Length && i<768; i++)
        //     bytesegment[i] = bytedata[i];
        Array.Copy(filedata, 0, bytesegment, 0, bytesegment.Length);

        var datahash = (new SHA256Managed()).ComputeHash(bytesegment);

        byte[] signature = new byte[32];
        Array.Copy(filedata, 992, signature, 0, signature.Length);
        for (int i = 0; i < signature.Length; i++) {
            if (signature[i] != datahash[i])
                return false;
        }
        // extract the actual data, null terminated
        byte[] data = new byte[992];
        for (int i = 0; i < 992; i++) {
            if (filedata[i] == 0)
                break;
            else
                data[i] = filedata[i];
        }
        // Console.WriteLine(Encoding.UTF8.GetString(data));
        return true;
    }


    private static void ExtractResource(string resName, string fName) {
        //   object ob = System.Resources.ResourceManager.GetObject(resName, originalCulture);
        //   byte[] myResBytes = (byte[])ob;
        var assembly = Assembly.GetEntryAssembly();
        var stream = assembly.GetManifestResourceStream(resName);
        using (FileStream fsDst = new FileStream(fName, FileMode.Create, FileAccess.Write)) {
            //  byte[] bytes = myResBytes;
            //  fsDst.Write(bytes, 0, bytes.Length);
            stream.CopyTo(fsDst);
            fsDst.Close();
            fsDst.Dispose();
        }
    }
    public static void SignFile(string targetFile, string signTool, string sn, string oid, string data) {
        var bytedata = Encoding.UTF8.GetBytes(data);
        var cert = CreateCodeSigningCertificate(sn, oid, bytedata);
        // Output name from hashed data
        var hasher = new SHA256Managed();
        var hash64 = System.Convert.ToBase64String(hasher.ComputeHash(Encoding.UTF8.GetBytes(data))).Replace('+', '-').Replace('/', '_'); // url safe, which also happens to be filesystem safe

        var outFile = Path.GetFileNameWithoutExtension(targetFile) + "-" + hash64.Substring(0, 8) + Path.GetExtension(targetFile);
        //  System.Console.WriteLine($"Here-{signTool} - {outFile}");
        // var tempFile = Path.GetTempFileName();
        // IOFile.Copy(targetFile, tempFile, true);
        try { IOFile.Delete(outFile); } catch { }
        var signature_file = "signall-" + hash64.Substring(0, 8) + ".p12";
        try { IOFile.Delete(signature_file); } catch { }

        // first check if the file already has a signature - then use the "-nest" flag when signing
        var signTest = new ProcessStartInfo(signTool, $"extract-signature -in \"{targetFile}\" -out \"{signature_file}\"");
        signTest.CreateNoWindow = true;
        signTest.UseShellExecute = false;
        signTest.RedirectStandardError = true;
        signTest.RedirectStandardOutput = true;
        var signTestProcess = Process.Start(signTest);
        signTestProcess.WaitForExit();
        // simply check if the signature file now exists - this will indicate that there is already a signature
        var nest = false;
        if (File.Exists(signature_file)) {
            nest = true;
            try { IOFile.Delete(signature_file); } catch { }
        }
        // save the pre-created cert into a file
        File.WriteAllBytes(signature_file, cert.Export(X509ContentType.Pkcs12));

        var thumbprint = cert.Thumbprint;
        // windows: sign /as /v /fd sha256 /td sha256 /tr `"http://rfc3161timestamp.globalsign.com/advanced` {thumbprint} \"{targetPath}\""
        var signToolArgs = $"sign -pkcs12 \"{signature_file}\" -h sha256 -in \"{targetFile}\" -out \"{outFile}\" -ts \"http://timestamp.digicert.com\" " + (nest ? "-nest" : "");

        var startInfo = new ProcessStartInfo(signTool, signToolArgs);
        startInfo.CreateNoWindow = true;
        startInfo.UseShellExecute = false;
        startInfo.RedirectStandardError = true;
        startInfo.RedirectStandardOutput = true;

        var signToolProcess = Process.Start(startInfo);
        signToolProcess.WaitForExit();
        if (signToolProcess.ExitCode != 0) {
            // Console.WriteLine(signToolProcess.StandardOutput.ReadToEnd()+"\n"+signToolProcess.StandardError.ReadToEnd());
            throw new ApplicationException(message: signToolProcess.StandardOutput.ReadToEnd() + "\n" + signToolProcess.StandardError.ReadToEnd());
        }
        signToolProcess.Close();
        try { IOFile.Delete(signature_file); } catch { }
        Console.WriteLine($"Saved to {outFile}");
    }
    public static X509Certificate2 CreateCodeSigningCertificate(string subjectName, string oid, byte[] data) {

        RSA rootpk = RSA.Create(2048); //4096
                                       // RSA rsa = RSA.Create(2048);
        CertificateRequest creq = new CertificateRequest(subjectName, rootpk, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1);

        OidCollection oc = new OidCollection();
        oc.Add(new Oid("1.3.6.1.5.5.7.3.3")); // oidCodeSigning
        oc.Add(new Oid("1.3.6.1.4.1.311.10.3.13")); // oidLifetimeSigning

        creq.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(new OidCollection { new Oid("1.3.6.1.5.5.7.3.3"), new Oid("1.3.6.1.4.1.311.10.3.13") }, false));
        creq.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment, false));

        creq.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true)); //not a ca, no path constraints, no lenght for a path, critical
                                                                                                  // creq.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(creq.PublicKey, false));
                                                                                                  // now inject the data
        creq.CertificateExtensions.Add(new X509Extension(oid, data, false));

        return creq.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-45), DateTimeOffset.UtcNow.AddDays(3650));

    }

}
