#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>
#if defined(_WIN32)
#include <wincrypt.h>
#elif defined(__APPLE__)
#include <Security/Security.h>
#endif

#include <fcntl.h>

//std::string SSLManagerInterface::getSSLErrorMessage(int code) {
//    // 120 from the SSL documentation for ERR_error_string
//    static const size_t msglen = 120;
//
//    char msg[msglen];
//    ERR_error_string_n(code, msg, msglen);
//    return msg;
//}


static int checkX509_STORE_error(char * err, size_t err_len) {
    unsigned long errCode = ERR_peek_last_error();
    if (ERR_GET_LIB(errCode) != ERR_LIB_X509 ||
        ERR_GET_REASON(errCode) != X509_R_CERT_ALREADY_IN_HASH_TABLE) {
        snprintf(err,err_len, "Error adding certificate to X509 store: %s" ,ERR_reason_error_string(errCode));
        return 0;
    }
    return 1;
}

#if defined(_WIN32)
// This imports the certificates in a given Windows certificate store into an X509_STORE for
// openssl to use during certificate validation.
static int importCertStoreToX509_STORE(LPWSTR storeName, DWORD storeLocation, X509_STORE* verifyStore, char * err, size_t err_len) {
    HCERTSTORE systemStore =
        CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, NULL, storeLocation, storeName);
    if (systemStore == NULL) {
        snprintf(err,err_len,"error opening system CA store: %m");
        return 0;
    }
    auto systemStoreGuard = MakeGuard([systemStore]() { CertCloseStore(systemStore, 0); });

    PCCERT_CONTEXT certCtx = NULL;
    while ((certCtx = CertEnumCertificatesInStore(systemStore, certCtx)) != NULL) {
        auto certBytes = static_cast<const unsigned char*>(certCtx->pbCertEncoded);
        X509* x509Obj = d2i_X509(NULL, &certBytes, certCtx->cbCertEncoded);
        if (x509Obj == NULL) {
            static const size_t msglen = 120;
            char msg[msglen];
            ERR_error_string_n(ERR_get_error(), msg, msglen);
            snprintf(err,err_len, "Error parsing X509 object from Windows certificate store %s" ,msg);
            retrn 0
        }

        int r
        r = X509_STORE_add_cert(verifyStore, x509Obj)
        X509_free(x509Obj);
        if (r != 1) {
            int status = checkX509_STORE_error(err,err_len);
            if (!status)
                return status;
        }
    }
    DWORD lastError = GetLastError();
    if (lastError != CRYPT_E_NOT_FOUND) {
        snprintf(err,err_len,"Error enumerating certificates: %s",errnoWithDescription(lastError));
        return 0;
    }

    return 1
}
#elif defined(__APPLE__)

//std::string OSStatusToString(OSStatus status) {
//    auto errMsg = makeCFTypeRefHolder(SecCopyErrorMessageString(status, NULL));
//    return std::string{CFStringGetCStringPtr(errMsg, kCFStringEncodingUTF8)};
//}

static int importKeychainToX509_STORE(X509_STORE* verifyStore, char * err, size_t err_len) {
    // First we construct CFDictionary that specifies the search for certificates we want to do.
    // These std::arrays make up the dictionary elements.
    // kSecClass -> kSecClassCertificates (search for certificates)
    // kSecReturnRef -> kCFBooleanTrue (return SecCertificateRefs)
    // kSecMatchLimit -> kSecMatchLimitAll (return ALL the certificates).
    const void* searchDictKeys[3] = {(void*)kSecClass, (void*)kSecReturnRef, (void*)kSecMatchLimit};
    const void* searchDictValues[3] = {(void*)kSecClassCertificate, (void*)kCFBooleanTrue, (void*)kSecMatchLimitAll};
    assert(sizeof(searchDictKeys)==sizeof(searchDictValues));

    CFDictionaryRef searchDict = CFDictionaryCreate(kCFAllocatorDefault,
                                                             searchDictKeys,
                                                             searchDictValues,
                                                             3, // key and value length
                                                             &kCFTypeDictionaryKeyCallBacks,
                                                             &kCFTypeDictionaryValueCallBacks);

    CFArrayRef result;
    OSStatus status;
    // Run the search against the default list of keychains and store the result in a CFArrayRef
    if ((status = SecItemCopyMatching(searchDict, (CFTypeRef*)(&result))) != 0) {
        char status_string[256];
        CFStringGetCString(SecCopyErrorMessageString(status, NULL),status_string,256,kCFStringEncodingUTF8);
        snprintf(err,err_len,"Error enumerating certificates: %s",status_string);
        return 0;
    }

    for (CFIndex i = 0; i < CFArrayGetCount(result); i++) {
        SecCertificateRef cert =
            (SecCertificateRef)CFArrayGetValueAtIndex(result, i);

        CFDataRef rawData = SecCertificateCopyData(cert);
        if (!rawData) {
            snprintf(err,err_len,"Error enumerating certificates: ???");
            return 0;
        }
        const uint8_t* rawDataPtr = CFDataGetBytePtr(rawData);

        // Parse an openssl X509 object from each returned certificate
        X509* x509Cert = d2i_X509(NULL, &rawDataPtr, CFDataGetLength(rawData));
        if (!x509Cert) {
            snprintf(err,err_len,"Error parsing X509 certificate from system keychain: %s",ERR_reason_error_string(ERR_peek_last_error()));
            return 0;
        }

        // Add the parsed X509 object to the X509_STORE verification store
        if (X509_STORE_add_cert(verifyStore, x509Cert) != 1) {
            int status = checkX509_STORE_error(err,err_len);
            if (!status)
                return status;
        }
    }

    return 1;
}
#endif

static int _setupSystemCA(SSL_CTX* context, char * err, size_t err_len) {
#if !defined(_WIN32) && !defined(__APPLE__)
    // On non-Windows/non-Apple platforms, the OpenSSL libraries should have been configured
    // with default locations for CA certificates.
    if (SSL_CTX_set_default_verify_paths(context) != 1) {
        snprintf(err, err_len, "error loading system CA certificates "
                "(default certificate file: %s default certificate path: %s )",
                X509_get_default_cert_file(),X509_get_default_cert_dir() );
        return 0;
    }
    return 1;
#else

    X509_STORE* verifyStore = SSL_CTX_get_cert_store(context);
    if (!verifyStore) {
        snprintf(err, err_len,"no X509 store found for SSL context while loading system certificates");
        return 0;
    }
#if defined(_WIN32)
    int status = importCertStoreToX509_STORE(L"root", CERT_SYSTEM_STORE_CURRENT_USER, verifyStore, err, err_len);
    if (!status) return status;
    return importCertStoreToX509_STORE(L"CA", CERT_SYSTEM_STORE_CURRENT_USER, verifyStore, err, err_len);
#elif defined(__APPLE__)
    return importKeychainToX509_STORE(verifyStore,err,err_len);
#endif
#endif
}

int main(int argc, char **argv) {
    char err_buf[1024];
    size_t err_len = 1024;
    char *err = err_buf;

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLSv1_method());
    if (ctx==NULL) {
        ERR_error_string_n(ERR_get_error(),err,err_len);
        printf("SSL_CTX_new error %s\n",err);
        exit(1);
    }
    int status = _setupSystemCA(ctx,err_buf,1024);
    if (!status)
        printf("err: %s",err_buf);


    FILE *f = fopen("mongodb.com.pem","r");
    X509 *cert = PEM_read_X509(f,NULL,NULL,NULL);

    X509_STORE *cert_store = X509_STORE_new();

    X509_STORE_CTX cert_ctx;

    X509_STORE_CTX_init(&cert_ctx,cert_store,cert,NULL);
    
    int r = X509_verify_cert(&cert_ctx);
    printf("verify %d\n",r);

}
