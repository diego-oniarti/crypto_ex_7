#include <boost/multiprecision/cpp_int.hpp>
#include <cstdio>
#include <filesystem>
#include <iostream>
#include <set>
#include <string>
#include <utility>
#include <curl/curl.h>
using namespace boost::multiprecision;

#define DEBUG
#define PROGFILE "progress"

typedef std::pair<uint1024_t, uint1024_t> interval_t;
typedef std::set<interval_t> M_t;

uint1024_t read_hex(std::string s);
std::string write_hex(uint1024_t n);
uint1024_t RSA(uint1024_t a, uint1024_t b, uint1024_t d, uint1024_t n);
bool checkPKCS(uint1024_t msg);
uint1024_t ceildiv(uint1024_t a, uint1024_t b) { return 1 + ((a-1) / b); }
inline uint1024_t max(uint1024_t a, uint1024_t b) {return a>b?a:b;}
inline uint1024_t min(uint1024_t a, uint1024_t b) {return a<b?a:b;}

int main(int argc, char *argv[]) {
    CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
    if(res) return (int)res;

#ifdef DEBUG
    std::string cypher_str = "600d7621dd076d88c076bf18f1bc9a65e51d9bdf1279b7ec0dfaa16e6e0fd3f996f686b2c95230f760bf222a14f4059538b3ed85e8b343a107aa083f042150a8591f0a0136a678f3530d27d0671359689bd735d7e8ce97ba56c44742c792c9c9cc0e43c63046cfac5d58a29b0f45c4fe1e77e4cc714ddd63669cf51f71fbc61b";
    std::string modulo_str = "6afa36c8cd07a91475bf7c36e86a0389166bb0ea27b556734be8949eb8a28d8a44bdbf7a773e34778731662c3a5775f2a456cf22e045b7e8678d0e145d907abf414311744107b7a377759fbf568d0e4844eefade6eec7c454721139d8378c4d8b7112997968e91a6b41f10ffd386a9439515b1846ed4f252aa6d5a775ad4e03b";
#else
    std::string cypher_str = "2d38aeb156ef11bc165989a12669b30cf20cda8a196288a2a24262c9b43bd715ba76dbd8c42337d4ec0d7d40a77fe4a5f37a5a59e0e5e5506abb588225d5f3483f4f4bde4e3771cec55f12c0dcca56f5d9a3110bc50dc47d7d04db8e4e57044574ca101301c1efc64a497af420b286fe6baf3a4adc883a2ed24956c8eb502817";
    std::string modulo_str = "9d7113232d0c3e6be3815fa6bcb431c29d8b38574f522126835734a685a49d7b735e933a1b7b9cf218211265d658d99d9ec2c44e04aabe8997c0d15f52a9f60b2534e8c9f29f50e051403a7fcd8c6d9db3cd62cd474ad78a24416af3aceffde9fa17de1b732d048b608364e2b99569255a525472baf1efacccefef705334b4b7";
#endif
    uint1024_t c = read_hex(cypher_str);
    uint1024_t n = read_hex(modulo_str);
    uint1024_t e = 65537;

    int k = 1024/8; // From the oracle
    uint1024_t B = ((uint1024_t)1)<<(8*(k-2)); // 2^(8*(k-2))

    uint1024_t s = 1;      // remark
    M_t M {{2*B, 3*B-1}};

    int saved_s = -1;
    if (std::filesystem::exists(PROGFILE)) {
        FILE *prog = fopen(PROGFILE, "r");
        int _ = fscanf(prog, "s: %d", &saved_s);
    }

    int i=1;
    do {
        uint1024_t s_prev = s;
        M_t M_prev = M;

        // 2.a
        if (i==1) {
            s = n/(3*B);
            if (saved_s != -1) s = saved_s;
            else{
                while (!checkPKCS(RSA(c,s,e,n))) s++;
                std::cout << "Found s: " << s << std::endl;

                FILE *prog = fopen(PROGFILE, "w");
                fprintf(prog, "s: %d\n", (int)s);
                fclose(prog);
            }
        } else if (M_prev.size()>=2) { // 2.b
            std::cout << "2b" << std::endl;
            while (!checkPKCS(RSA(c,++s,e,n))) ;
        } else if (M_prev.size()==1) { // 2.c
            std::cout << "2c" << std::endl;
            uint1024_t a = M_prev.begin()->first;
            uint1024_t b = M_prev.begin()->second;

            uint1024_t r = ceildiv(2 * (b * s_prev - 2 * B), n);
            std::cout << a << "\n" << b << "\n" << r << std::endl;

            while (true) {
                uint1024_t s_min = ceildiv(2*B + r*n, b);
                uint1024_t s_max = (3*B + r*n) / a; // floor((3B - 1 + r*n)/a)

                for (s = s_min; s<=s_max; s++) {
                    if (checkPKCS(RSA(c,s,e,n))) goto step2Cend;
                }

                r++;
                std::cout << r << "\n";
            }
        }
step2Cend:

        // Step 3
        M.clear();
        for (interval_t inter: M_prev) {
            for (uint1024_t r = (inter.first*s-3*B+1)/n; r <= (inter.second*s-2*B)/n; r++) {
                uint1024_t a = max(inter.first, ceildiv(2*B+r*n, s));
                uint1024_t b = min(inter.second, (3*B -1+r*n)/s);
                if (a<=b) M.insert({{a,b}});
            }
        }

        i++;

        if (M.empty()) {
            std::cout << "AAAAAAAA" << std::endl;
            exit(1);
        }
    }while(M.size()!=1 || M.begin()->first!=M.begin()->second);

    curl_global_cleanup();
    return 0;
}

uint1024_t read_hex(std::string s) {
    uint1024_t n = 0;
    const char* c = s.c_str();
    unsigned int byte;
    int shift = 0;
    for (size_t i=0; i<s.length(); i+=2) {
        sscanf(c+i, "%2x", &byte);
        n |= ((uint1024_t)byte)<<(1024-(++shift)*8);
    }
    return n;
}

std::string write_hex(uint1024_t n) {
    std::stringstream ss;
    ss << std::hex << std::nouppercase << n;
    return ss.str();
}

// uint1024_t RSA(uint1024_t a, uint1024_t b, uint1024_t d, uint1024_t n) {
//     uint1024_t result = 1;
//     b = b % n;
//     while (d > 0) {
//         if (d & 1) result = (result * b) % n;
//         d >>= 1;
//         b = (b * b) % n;
//     }
//     return (a * result) % n;
// }

uint1024_t pow_mod(uint1024_t base, uint1024_t exp, uint1024_t mod) {
    uint1024_t result = 1;
    base = base % mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        exp = exp >> 1;
        base = (base * base) % mod;
    }
    return result;
}

uint1024_t RSA(uint1024_t c, uint1024_t s, uint1024_t e, uint1024_t n) {
    return (c * pow_mod(s, e, n)) % n;
}

size_t curlWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    ((std::string*)userdata)->append((char*)ptr, size * nmemb);
    return size * nmemb;
}


bool checkPKCS(uint1024_t msg) {
#ifdef DEBUG
    std::string BASE_URL = "127.0.0.1:8000/decrypt?c=";
#else
    std::string BASE_URL = "https://medieval-adelle-jonistartuplab-17499dda.koyeb.app/decrypt?c=";
#endif
    std::string HEX = write_hex(msg);
    std::string URL = BASE_URL+HEX;

    CURL *curl;

    curl = curl_easy_init();
    if(!curl) return false;

    std::string response;
    curl_easy_setopt(curl, CURLOPT_URL           , URL.c_str());
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION , curlWriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA     , &response);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, true);

    long code;
    CURLcode res = curl_easy_perform(curl);
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    curl_easy_cleanup(curl);

    if (!(res == CURLE_OK || code==500)) {
        fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        return false;
    }

    if (code==500) {
        return false;
    }

    return true;
}
