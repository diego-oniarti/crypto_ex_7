#include <cstdint>
#include <deque>
#include <vector>
#define PROGFILE "progress"

#include <gmpxx.h>
#include <set>
#include <string>

typedef mpz_class bigint;
typedef std::pair<bigint, bigint> interval_t;
typedef std::set<interval_t> M_t;

std::string write_hex(bigint n);
bigint RSA(bigint a, bigint b, bigint d, bigint n);
bool checkPKCS(bigint msg);
std::deque<uint8_t> trimMsg(bigint m);
inline bigint ceildiv(bigint a, bigint b) { return 1 + ((a-1) / b); }
inline bigint max(bigint a, bigint b) {return a>b?a:b;}
inline bigint min(bigint a, bigint b) {return a<b?a:b;}
