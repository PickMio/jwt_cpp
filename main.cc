#include "jwt.h"

int main(int argc, char *argv[]){    
    std::string iss = std::string("test@n.iam.gserviceaccount.com");
    std::string scope = std::string("https://www.googleapis.com/auth/androidpublisher");
    std::string aud = std::string("https://oauth2.googleapis.com/token");
    std::string key = std::string("vmkjgfioasubva3fdas34");
    std::string pass = std::string("");

    
    jwt j(iss, aud, scope, key, pass);
    std::string ret = j.get_jwt_code();
    cout << ret << endl;
    return 0;

}


