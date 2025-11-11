#include "utils.h"
#include <deque>
#include <iomanip>
#include <sstream>
#include <cstdio>
#include <iomanip>
#include <iostream>
#include <ostream>
#include <string>
#include <curl/curl.h>
#include <gmp.h>
#include <gmpxx.h>

std::string write_hex(bigint n) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0') << std::setw(256) << std::nouppercase << n;
    std::string h = ss.str();
    int k = 1024/8; // From the oracle
    size_t target = 2 * (size_t)k;
    if (h.size() < target) h = std::string(target - h.size(), '0') + h;
    return h;
}

bigint RSA(bigint c, bigint s, bigint e, bigint n) {
    bigint result;
    mpz_powm(result.get_mpz_t(), s.get_mpz_t(), e.get_mpz_t(), n.get_mpz_t());
    result = (c * result) % n;
    return result;
}


size_t curlWriteCallback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    ((std::string*)userdata)->append((char*)ptr, size * nmemb);
    return size * nmemb;
}

bool checkPKCS(bigint msg) {
#ifdef DEBUG
    std::string BASE_URL = "127.0.0.1:8000/decrypt?c=";
#else
    std::string BASE_URL = "https://juicy-allyn-mystic-rogue-04c667cf.koyeb.app/decrypt?c=";
#endif
    std::string HEX = write_hex(msg);
    std::string URL = BASE_URL+HEX;

a:
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
        goto a;
    }

    if (code==500) {
        return false;
    }

    return true;
}

std::deque<uint8_t> trimMsg(bigint m) {
    std::deque<uint8_t> ret;

    bigint tmp = m;

    while (tmp > 0) {
        ret.push_front((uint8_t)(mpz_get_ui(tmp.get_mpz_t()) & 0xFF));
        tmp >>= 8;
    }

    while (ret[0]!=0) ret.pop_front();
    ret.pop_front();

    return ret;
}
