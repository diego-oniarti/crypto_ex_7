#include "utils.h"

#include <cstdint>
#include <cstdio>
#include <curl/curl.h>
#include <filesystem>
#include <gmp.h>
#include <iomanip>
#include <iostream>
#include <ostream>

int main(int argc, char *argv[]) {
    CURLcode res = curl_global_init(CURL_GLOBAL_ALL);
    if (res) return (int)res;

#ifdef DEBUG
    std::string cypher_str = "09b9e926d8f0c868723d19e9931ddadadde87caa06e92e832920058369398bddc359e233c08fd50f61ab15ef28f01b81d1b402144f14013c13c141818e993a41744239815b4d71a400937b1ecafb07207c70f2fad2796bbb94bbf9669655e81a17825c9f5c0538d6584b03f131e54822121984acb9fae4bef00b19cc7a2da087";
    std::string modulo_str = "a093edb98a93189211f232572d3e9204e652690bdedb91641565fe91640410f388fd155c5ac7c00a132b0066bc021d8189249000fe9befeeadc9a91e4806becbecbe5835f71179b43803100586cddf4cbfa9410c1bf7aa0b7a86deb8924659c7b8f1fee25e80ddd97f9524eebc25c1dd73dda168c57c0c92d06b73c2afdb5c09";
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
            s = n/(3*B);
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

    FILE *fout = fopen("result.txt", "w");
    gmp_fprintf(fout, "%Zd\n", m.get_mpz_t());
    for (uint8_t t: trimmed) {
        fprintf(fout, "%c", (char)t);
    }
    fprintf(fout, "\n");
    fclose(fout);

    return 0;


    return 0;
}
