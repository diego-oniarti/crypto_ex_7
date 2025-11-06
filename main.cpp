#include "utils.h"

#include <cstdint>
#include <curl/curl.h>
#include <filesystem>
#include <iomanip>
#include <iostream>
#include <ostream>

int main(int argc, char *argv[]) {
    CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
    if (res) return (int)res;

#ifdef DEBUG
    std::string cypher_str = "78f9b8444a5ddfaff5734e358917efe50af522065ddf868592c28ea32fe92ee008a6388e37ae5dbc6bf44a83051829c3fb8e37bd617c0b44c2449854b6efa67037ab99b77dd0941dd2be69fb3fd66b0cef6f59310a47331d053b5f379e067e207ba08026362b4ba3aa7ba118a34e63530a54f4d98ec0940a7e5062db0a0d7020";
    std::string modulo_str = "9e928bc859ee0c34adfa648750f4ee5bd1c4f16b8cd77ec4430e537e1677485bdba49a17c44926d9af76d1dcd97f85149c63b57f978186c7dfff0fe0316203fe318a1bff303a77982ac23280c1cc5cc0f933f1849a433b96310a79aba0a2c6da65647ea45bfbead69ab1f22bf88a358404e8298cdb43188ba623279ce74278e1";
#else
    std::string cypher_str = "2D38AEB156EF11BC165989A12669B30CF20CDA8A196288A2A24262C9B43BD715BA76DBD8C42337D4EC0D7D40A77FE4A5F37A5A59E0E5E5506ABB588225D5F3483F4F4BDE4E3771CEC55F12C0DCCA56F5D9A3110BC50DC47D7D04DB8E4E57044574CA101301C1EFC64A497AF420B286FE6BAF3A4ADC883A2ED24956C8EB502817";
    std::string modulo_str = "9D7113232D0C3E6BE3815FA6BCB431C29D8B38574F522126835734A685A49D7B735E933A1B7B9CF218211265D658D99D9EC2C44E04AABE8997C0D15F52A9F60B2534E8C9F29F50E051403A7FCD8C6D9DB3CD62CD474AD78A24416AF3ACEFFDE9FA17DE1B732D048B608364E2B99569255A525472BAF1EFACCCEFEF705334B4B7";
#endif
    bigint c(cypher_str.c_str(), 16);
    bigint n(modulo_str.c_str(), 16);
    bigint e = 65537;

    int k = 1024/8; // From the oracle
    bigint B(1);
    B <<= 8*(k-2);

    bigint s(1);      // remark
    M_t M {{2*B, 3*B-1}};

    bigint saved_s = -1;
    if (std::filesystem::exists(PROGFILE)) {
        FILE *prog = fopen(PROGFILE, "r");
        int _ = gmp_fscanf(prog, "s: %Zd", saved_s.get_mpz_t());
    }

    bigint i=1;
    do {
        bigint s_prev = s;
        M_t M_prev = M;

        // 2.a
        if (i==1) {
            s = ceildiv(n, (3*B));
            if (saved_s != -1) s = saved_s;
            while (!checkPKCS(RSA(c,s,e,n))) {
                s++;
                std::cout << s << "\n";
            }
            std::cout << "Found s: " << s << std::endl;

            FILE *f = fopen(PROGFILE, "w");
            gmp_fprintf(f, "s: %Zd\n", s.get_mpz_t());
            fclose(f);

        } else if (M_prev.size()>=2) { // 2.b
            std::cout << "2b\n";
            while (!checkPKCS(RSA(c,++s,e,n))) {
                std::cout << s << "\n";
            }
        } else if (M_prev.size()==1) { // 2.c
            std::cout << "2c\n";
            bigint a = M_prev.begin()->first;
            bigint b = M_prev.begin()->second;

            bigint r = ceildiv(2 * (b * s_prev - 2 * B), n);

            while (true) {
                std::cout << "r: " << r << "\n";
                bigint s_min = ceildiv(2*B + r*n, b);
                bigint s_max = (3*B -1 + r*n) / a;

                for (s = max(s,s_min); s<=s_max; s++) {
                    if (checkPKCS(RSA(c,s,e,n))) goto step2Cend;
                }

                r++;
            }
        }
step2Cend:

        // Step 3
        M.clear();
        M_t tmpM;
        for (interval_t inter: M_prev) {
            for (bigint r = ceildiv(inter.first*s-3*B+1, n); r <= (inter.second*s-2*B)/n; r++) {
                bigint a = max(inter.first, ceildiv(2*B+r*n, s));
                bigint b = min(inter.second, (3*B -1+r*n)/s);
                if (a<=b) tmpM.insert({{a,b}});
            }
        }

        // Merge overlap
        for (interval_t nuovo: tmpM) {
            auto it = M.begin();
            while (it!=M.end()) {
                interval_t presente = *it;
                if (!(nuovo.first>presente.second || nuovo.second<presente.first)) {
                    nuovo.first = min(nuovo.first, presente.first);
                    nuovo.second = max(nuovo.second, presente.second);
                    it = M.erase(it);
                }else{
                    it++;
                }
            }

            M.insert(nuovo);
        }

        i++;

        if (M.empty()) {
            std::cout << "AAAAAAAA" << std::endl;
            exit(1);
        }
    }while(M.size()!=1 || M.begin()->first!=M.begin()->second);
    curl_global_cleanup();

    // step 4
    bigint m = M.begin()->first;
    std::cout << "m:\n" << std::setfill('0') << std::setw(256) << std::hex << m << std::endl;

    std::cout << "\n";

    std::deque<uint8_t> trimmed = trimMsg(m);
    std::cout << "Message: ";
    for (uint8_t t: trimmed) {
        std::cout << t;
    }
    std::cout << std::endl;

    return 0;


    return 0;
}
