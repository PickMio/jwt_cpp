#include <iostream>
#include <string.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

using namespace std;




class jwt{
    public:
        jwt(const std::string& iss, 
            const std::string aud, 
            const std::string& scope, 
            const std::string& key,
            const std::string& pass);
        std::string get_jwt_code();


    private:
        std::string generate_jwt();
        void new_en_prefix();
        void new_en_claim();
        std::string new_claim();
        std::string get_sign();
        EVP_PKEY* load_private_key(const std::string& key, const std::string& pass);
        std::string bc_base64_encode(const void *data, int data_len);
        std::string bc_url_base64_encode(const void *data, int data_len);

    private:
        std::string iss_;
        std::string scope_;
        int exp_;
        std::string key_;
        std::string pass_;
        std::string aud_;
        std::string en_prefix_;
        std::string en_claim_;
};

