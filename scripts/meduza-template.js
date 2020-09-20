// Uncomment next two lines for testing purposes only
// var certs = {};
// var domains = {};

// Allocated certs
var allocatedCerts = {};

// Allocate certificates
console.log("[*] Allocating memory for certs...");
for (var hash in certs) {
    var bytes = certs[hash];
    var certBytes = Memory.alloc(bytes.length);
    certBytes.writeByteArray(bytes);
    allocatedCerts[hash] = {"address": certBytes, "length": bytes.length};
    console.log("[*] Just allocated a memory for the cert with the raw bytes SHA256 hash: " + hash);
}

// Get SecCertificateCreateWithBytes pointer
console.log("[*] Looking for SecCertificateCreateWithBytes()...");
var SecCertificateCreateWithBytes_prt = Module.findExportByName("Security", "SecCertificateCreateWithBytes");

// SecCertificateCreateWithBytes()
var SecCertificateCreateWithBytes = new NativeFunction(
    SecCertificateCreateWithBytes_prt, "pointer", ["pointer", "pointer", "uint64"]
);

// SecCertificateCopyCommonName()
console.log("[*] Looking for SecCertificateCopyCommonName()...");
var SecCertificateCopyCommonName = new NativeFunction(
    Module.findExportByName("Security", "SecCertificateCopyCommonName"), "uint64", ["pointer", "pointer"]
);

// CFStringGetCStringPtr()
console.log("[*] Looking for CFStringGetCStringPtr()...");
var kCFStringEncodingASCII = 0x600;
var CFStringGetCStringPtr = new NativeFunction(
    Module.findExportByName("CoreFoundation", "CFStringGetCStringPtr"), "pointer", ["pointer", "uint64"]
);

// Catch the certificates
function spoofCertificates() {
    // Hook SecCertificateCreateWithBytes()
    console.log("[*] Hooking SecCertificateCreateWithBytes()...");
    Interceptor.replace(SecCertificateCreateWithBytes_prt, new NativeCallback(function(something, certAddress, certLength) {
        // Get the certificate CN
        var result = SecCertificateCreateWithBytes(something, certAddress, certLength);
        var cnCFString_prt = Memory.alloc(8);
        SecCertificateCopyCommonName(result, cnCFString_prt);
        var strPtr = cnCFString_prt.readPointer();
        if (strPtr == null) return result;
        var cn = CFStringGetCStringPtr(cnCFString_prt.readPointer(), kCFStringEncodingASCII).readCString();
        if (cn == null) return result;
        // Check the cn and replace the certificate, if it's required
        console.log("[*] Intercepted certificate with CN: " + cn);
        if ((cn.indexOf(" ") < 0) && (cn.indexOf(".") > -1)) {
            if (cn in domains) {
                var hash = domains[cn];
                var certBytes = allocatedCerts[hash]["address"];
                var certLength = allocatedCerts[hash]["length"];
                // Do spoof the certificate
                console.log("[*] Spoofing the cert with CN: " + cn + ", the original cert raw bytes SHA256 hash: " + hash + "...");
                return SecCertificateCreateWithBytes(something, certBytes, certLength);
            } else {
                // It's a domain, but it was not spoofed
                console.log("[!] The domain with CN: " + cn + " was NOT spoofed! SSL unpinning may be particular!");
            }
        }
        // Return the certificate
        return result;
    }, "pointer", ["pointer", "pointer", "uint64"]));
    console.log("[*] SecCertificateCreateWithBytes() hooked!");
}
spoofCertificates();