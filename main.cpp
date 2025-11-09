/*
 * Authors: Diego Oniarti, Alessandro Marostica
 * Team:    Mango
 *
 * m:
 * 00 02 ffffb310dece2e564839665947096cc502677a7902912a2383926818568df045ddd6cc3c23120bdb031facef9c2f088c95f6d9d5b303ada275a2ed48f3839e79d51819d8f56049de67ffd8c027ded7504390205ca071396c82827ee47ddff4223b18a86b306e61bd7c8ee540d8341b59a284ddbd9cd1c1f99e02d9677209
 *
 * m does not appear to follow the PKCS format `00 02 padding 00 data` as there is no zero byte to terminate the padding
 */

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
    std::string cypher_str = "00dda05e8c45f2abaa1c0e6cb26ccb97d665b7f418cd39973b9ee9cee922592c1509193f044787ef9d9d84b1d6a1d51b8681aa7d508e3e6b29edb95cdeeb42713c2891f032617521d1d8a728b3737142168f38e5c09b8609cbcd8956fbc2abd6771dce68a95283833100ce814b6de0c41d80b647dc7a0874b78023b34948cedc88";
    std::string modulo_str = "e916513f25cdd6fb9ab0a8ae98a081dd8f448b9926d4f1974a87e8dad23ade3b9c6c73d7720a2fb210feeef4c3bea2cf5a9a7374ab8b40e14f30f66d484d21585692e845fe34e5c60831f1389d4714f83209cba7be41adced0547dc29d8bf5d19bb94d5c728ee15118dba537572a020f5560b1ecc7ab2de9ab8c4f3129c57539";
#else
    std::string cypher_str = "2d38aeb156ef11bc165989a12669b30cf20cda8a196288a2a24262c9b43bd715ba76dbd8c42337d4ec0d7d40a77fe4a5f37a5a59e0e5e5506abb588225d5f3483f4f4bde4e3771cec55f12c0dcca56f5d9a3110bc50dc47d7d04db8e4e57044574ca101301c1efc64a497af420b286fe6baf3a4adc883a2ed24956c8eb502817";
    std::string modulo_str = "9d7113232d0c3e6be3815fa6bcb431c29d8b38574f522126835734a685a49d7b735e933a1b7b9cf218211265d658d99d9ec2c44e04aabe8997c0d15f52a9f60b2534e8c9f29f50e051403a7fcd8c6d9db3cd62cd474ad78a24416af3aceffde9fa17de1b732d048b608364e2b99569255a525472baf1efacccefef705334b4b7";
#endif
    bigint c(cypher_str.c_str(), 16);
    bigint n(modulo_str.c_str(), 16);
    bigint e = 65537; // From the oracle

    int k = 1024/8; // From the oracle
    bigint B(1);
    B <<= 8*(k-2);

    bigint s(1);      // remark
    M_t M {{2*B, 3*B-1}};

    // Load the s_1 if it was saved by a previous run of the program
    bigint saved_s = -1;
    if (std::filesystem::exists(PROGFILE)) {
        FILE *prog = fopen(PROGFILE, "r");
        int _ = gmp_fscanf(prog, "s: %Zd", saved_s.get_mpz_t());
    }

    bigint i=1;
    do {
        // s_i-1 and M_i-1
        bigint s_prev = s;
        M_t M_prev = M;

        if (i==1) { // 2.a
            s = ceildiv(n, 3*B);
            if (saved_s != -1) s = saved_s;
            while (!checkPKCS(RSA(c,s,e,n))) {
                s++;
                std::cout << s << "\n";
            }
            std::cout << "Found s: " << s << std::endl;

            // Save s_1
            FILE *f = fopen(PROGFILE, "w");
            gmp_fprintf(f, "s: %Zd\n", s.get_mpz_t());
            fclose(f);
        } else if (M_prev.size()>=2) { // 2.b
            while (!checkPKCS(RSA(c,++s,e,n))) std::cout << "2b: " << s << "\n";
        } else if (M_prev.size()==1) { // 2.c
            std::cout << "2c\n";
            bigint a = M_prev.begin()->first;
            bigint b = M_prev.begin()->second;

            bigint r = ceildiv(2 * (b*s_prev - 2*B), n);
            while (true) {
                std::cout << "r: " << r << "\n";
                bigint s_min = ceildiv(2*B + r*n, b);
                bigint s_max = ceildiv(3*B + r*n, a);

                for (s = max(s,s_min); s<s_max; s++) {
                    if (checkPKCS(RSA(c,s,e,n))) goto step2Cend;
                }

                r++;
            }
        }
step2Cend:

        // Step 3
        M_t tmpM;
        for (interval_t inter: M_prev) {
            for (
                    bigint r = ceildiv(inter.first*s - 3*B + 1, n);
                    r <= (inter.second*s - 2*B)/n;
                    r++
                ) {
                bigint a = max(inter.first, ceildiv(2*B+r*n, s));
                bigint b = min(inter.second, (3*B -1+r*n)/s);
                if (a<=b) tmpM.insert({{a,b}});
                else std::cerr << "What?!" << std::endl;
            }
        }

        // Merge overlaps
        M.clear();
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
            std::cerr << "AAAAAAAA" << std::endl;
            exit(1);
        }
    }while(M.size()!=1 || M.begin()->first!=M.begin()->second);
    curl_global_cleanup();

    std::cout << "s:\n" << std::setfill('0') << std::setw(256) << std::hex << s << std::endl;

    // step 4
    bigint m = (M.begin()->first) % n;
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
}
