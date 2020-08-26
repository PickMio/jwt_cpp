#include "jwt.h"
jwt::jwt(const std::string& iss, const std::string aud, const std::string& scope, const std::string& key,
        const std::string& pass){
    iss_ = iss;
    scope_ = scope;
    key_ = key;
    aud_ = aud;
    pass_ = pass;
    new_en_prefix();
    new_en_claim();
}

std::string jwt::get_jwt_code(){
    int now = time(NULL);
    if(now > exp_){        
        new_en_claim();
    }
    std::string code = generate_jwt();
    return code;
}

std::string jwt::generate_jwt(){
    return en_prefix_ + "." + en_claim_ + "." + get_sign();
}

void jwt::new_en_prefix(){
    std::string prefix = "{\"alg\":\"RS256\",\"typ\":\"JWT\"}";
    en_prefix_ = bc_url_base64_encode(prefix.c_str(), prefix.size());
}

void jwt::new_en_claim(){
    std::string claim = new_claim();
    en_claim_ = bc_url_base64_encode(claim.c_str(), claim.size());
}

std::string jwt::new_claim(){
    time_t now = time(NULL);
    exp_ = now + 3600;
    char buf[8192] = {0};
    sprintf(buf, "{\"iss\":\"%s\",\"aud\":\"%s\", \"scope\":\"%s\",\"exp\":%d,\"iat\":%d}",
            iss_.c_str(), aud_.c_str(), scope_.c_str(), exp_, now);

    return std::string(buf);
}

std::string jwt::get_sign(){
    std::string data = en_prefix_ + "." + en_claim_;
    EVP_PKEY *pk = load_private_key(key_, pass_);
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if(NULL == ctx){        
        return "";
    }
    if (!EVP_SignInit(ctx,EVP_sha256() )){        
        return "";
    }
    std::string res(EVP_PKEY_size(pk), '\0');
    unsigned int len = 0;
    if(!EVP_SignUpdate(ctx, data.data(), data.size())){        
        return "";

    }

    if(EVP_SignFinal(ctx, (unsigned char*)res.data(), &len, pk) == 0){        
        return "";

    }

    EVP_PKEY_free(pk);
    EVP_MD_CTX_destroy(ctx);
    res.resize(len);

    std::string sign_code = bc_url_base64_encode(res.c_str(), res.size());
    return sign_code;
}


EVP_PKEY* jwt::load_private_key(const std::string& key, const std::string& pass){
    BIO *priv = BIO_new(BIO_s_mem());
    if(NULL == priv){        
        return NULL;

    }   
    const int len = static_cast<int>(key.size());
    if(BIO_write(priv, key.data(), len) != len){        
        return NULL;
    }   
    EVP_PKEY *pk = PEM_read_bio_PrivateKey(priv, NULL, NULL, const_cast<char*>(pass.c_str()));
    if(NULL == pk){        
        return NULL;

    }
    return pk;
}

std::string jwt::bc_base64_encode(const void *data, int data_len)
{
    BIO *b64 = BIO_new(BIO_f_base64());
    BIO *bio = BIO_new(BIO_s_mem());

    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, data_len);
    BIO_ctrl(bio, BIO_CTRL_FLUSH, 0, NULL);

    BUF_MEM *bptr = NULL;
    BIO_get_mem_ptr(bio, &bptr);

    unsigned slen = (unsigned)bptr->length;
    std::string ret(bptr->data, slen);
    BIO_free_all(bio);
    return ret;
}

std::string jwt::bc_url_base64_encode(const void *data, int data_len){
    std::string code = bc_base64_encode(data, data_len);
    int equalSize = 0;
    for(size_t c = 0; c < code.size(); ++c){
        if(code[c] == '/'){
            code[c] = '_';

        }else if(code[c] == '+'){
            code[c] = '-';

        }else if(code[c] == '='){            
            equalSize++; 
        }
    }    

    std::string ret = std::string(code.begin(), code.end() - equalSize);
    
    return ret;

}

