#include <variant>
#include <array>
#include <cstdint>
#include <string>

using AES_128_key = std::array<uint8_t, 16>;
using AES_192_key = std::array<uint8_t, 24>;
using AES_256_key = std::array<uint8_t, 32>;



using AES_key_t = std::variant<AES_128_key,AES_192_key,AES_256_key>;
 
using AES_state_t = std::array<uint32_t,4U>;

typedef struct{
    uint8_t q;
    uint8_t r;
} pol_div_t;

typedef struct{
    uint8_t g;
    uint8_t inv;
}pol_gcd_t;

namespace AES{
    static uint8_t inverses[256] = {0};
    pol_div_t polynomialDivision( uint8_t, uint8_t );
    uint8_t RijndelPolynomialMul(uint8_t, uint8_t);
    uint8_t computeInverse(uint8_t);
    uint8_t S_Box(uint8_t);
    uint8_t inverse_S_Box(uint8_t);
    uint32_t RotWord(uint32_t);
    uint32_t SubWord(uint32_t);
    void AES128_Key_Scheduler_function(int, AES_128_key, uint32_t[], uint32_t[]);
    void AES192_Key_Scheduler_function(int, AES_192_key, uint32_t[], uint32_t[]);
    void AES256_Key_Scheduler_function(int, AES_256_key, uint32_t[], uint32_t[]);
    void AES_Round_Constants_function(int, uint32_t[]);
    uint8_t xtime(uint8_t);
};

class AES_Key_Scheduler{

    uint32_t rcon[10] = {0};
    AES_128_key _round_keys[15] = {};
    size_t n_key_words;
    size_t currIndex = 0;
    
public:
    size_t n_rounds = 0;
    AES_Key_Scheduler() = delete;
    AES_Key_Scheduler(AES_key_t);
    AES_128_key next(); 
};


class AES_Cipher {
    AES_key_t key;
    AES_Key_Scheduler sched;

    AES_state_t _AddRoundKey(AES_state_t , AES_128_key );
    AES_state_t _SubBytes(AES_state_t );
    AES_state_t _ShiftRows(AES_state_t );
    AES_state_t _MixColumns(AES_state_t );

public:
    AES_Cipher(AES_key_t);
    std::string cipher(std::string );
    std::string decipher(std::string );
};


class AESException : std::exception{
    const char* msg;
public:
    AESException();
    AESException(const char* msg);
    const char* what() const noexcept override;
};