#include <aes.hpp>
#include <cmath>
#include <type_traits>

int degree(uint16_t p){
    return floor(log2(p));
}

/*Computes polynomial division on polynomials ciphered as bytes*/
pol_div_t AES::polynomialDivision( 
    uint8_t a,
    uint8_t b
){
    uint8_t q = 0;
    while(degree(a) >= degree(b)){
        int shift = degree(a) - degree(b);
        q ^= (1 << shift);
        a ^= (b << shift);
    }
    return {q,a};
}

uint8_t AES::RijndelPolynomialMul(uint8_t a, uint8_t b){
    uint8_t r = 0;
    for(int i = 0; i < 8; i++){
        if( b & 1){
            r^= a;
        }
        uint8_t carry = a & 0x80;
        a <<= 1;
        if(carry){
            a ^= 0x1B;
        }
        b >>= 1;
    }
    return r;
}

uint8_t AES::computeInverse(uint8_t a){
    
    if (a == 0) {
        return 0;
    }

    uint16_t u = a;
    uint16_t v = 0x11B;
    uint16_t g1 = 1;
    uint16_t g2 = 0;

    while (u != 1 && v != 1) {
        // remove factors of x (u even)
        while ((u & 1) == 0) {
            u >>= 1;
            if ((g1 & 1) == 0) {
                g1 >>= 1;
            } else {
                g1 = (g1 ^ 0x11B) >> 1;
            }
        }

        if (degree(u) < degree(v)) {
            std::swap(u, v);
            std::swap(g1, g2);
        }

        u ^= v;
        g1 ^= g2;
    }

    // whichever of u or v became 1 holds the gcd; return the associated coeff
    if (u == 1) {
        return (uint8_t)g1;
    } else {
        return (uint8_t)g2;
    }
}

uint8_t AES::S_Box(uint8_t b){
    /*First, compute inverse*/
    uint8_t inv = inverses[b];
    return inv ^
        ((inv << 1) | (inv >> 7)) ^
        ((inv << 2) | (inv >> 6)) ^
        ((inv << 3) | (inv >> 5)) ^
        ((inv << 4) | (inv >> 4)) ^
        0x63;
}

uint8_t AES::inverse_S_Box(uint8_t b){
    uint8_t r = b ^
        ((b << 1) | (b >> 7)) ^
        ((b << 3) | (b >> 5)) ^
        ((b << 6) | (b >> 2)) ^
        0x05;
    return inverses[r];
}

uint32_t AES::RotWord(uint32_t w){
    uint8_t upper = w & 0xFF000000;
    w <<= 8;
    w |= upper;
    return w;
}

uint32_t AES::SubWord(uint32_t w){
    uint32_t result = 0U;
    for(int i = 0; i < 4; i++){
        uint8_t transformed = AES::S_Box(w >> 24);
        result |= transformed;
        w <<= 8;
        result <<= 8;
    }
    return result;
}

void AES::AES_Round_Constants_function(int round, uint32_t round_constants[]){
    if(round == 0){ //First round
        round_constants[round] = 1;
    }else{
        if(round_constants[round-1] < 0x80){
            round_constants[round] = 2*round_constants[round-1];
        }else{
            round_constants[round] = (((2*round_constants[round-1]) ^ 0x11B) % 0x100);
        }
    }
}


void AES::AES128_Key_Scheduler_function(int i,AES_128_key key, uint32_t round_word_keys[], uint32_t round_constants[]){
    /*First case*/
    int key_size = 4;
    if( i <  key_size){
        round_word_keys[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2]) << 8 | (key[4*i+3]);
    }else{
        if( i % key_size == 0 ){
            round_word_keys[i] = round_word_keys[i-key_size] ^ AES::SubWord(AES::RotWord(round_word_keys[i-1])) ^ round_constants[i/key_size];
        }else{
            round_word_keys[i] = round_word_keys[i-key_size] ^ round_word_keys[i-1];
        }
    }
}

void AES::AES192_Key_Scheduler_function(int i,AES_192_key key, uint32_t round_word_keys[], uint32_t round_constants[]){

    int key_size = 6;
    if( i <  key_size){
        round_word_keys[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2]) << 8 | (key[4*i+3]);
    }else{
        if( i % key_size == 0 ){
            round_word_keys[i] = round_word_keys[i-key_size] ^ AES::SubWord(AES::RotWord(round_word_keys[i-1])) ^ round_constants[i/key_size];
        }else if( i % key_size == 4){
            round_word_keys[i] = round_word_keys[i-key_size] ^ AES::SubWord(round_word_keys[i-1]);
        }
        else{
            round_word_keys[i] = round_word_keys[i-key_size] ^ round_word_keys[i-1];
        }
    }
}

void AES::AES256_Key_Scheduler_function(int i,AES_256_key key, uint32_t round_word_keys[], uint32_t round_constants[]){
    /*First case*/
    int key_size = 4;
    if( i <  key_size){
        round_word_keys[i] = (key[4*i] << 24) | (key[4*i+1] << 16) | (key[4*i+2]) << 8 | (key[4*i+3]);
    }else{
        if( i % key_size == 0 ){
            round_word_keys[i] = round_word_keys[i-key_size] ^ AES::SubWord(AES::RotWord(round_word_keys[i-1])) ^ round_constants[i/key_size];
        }else if(i % key_size == 4){
            round_word_keys[i] = round_word_keys[i-key_size] ^ AES::SubWord(round_word_keys[i-1]);
        }else{
            round_word_keys[i] = round_word_keys[i-key_size] ^ round_word_keys[i-1];
        }
    }
}

uint8_t AES::xtime(uint8_t n){
    return (n << 1) ^ ((n & 0x80) ? 0x1B : 0x00);
}


AES_128_key fromui32ToAES_128(const uint32_t* num){
    uint32_t w1= num[0], w2= num[1], w3= num[2], w4= num[3];
    return {
        (uint8_t) w1 >> 24, (uint8_t) w1 >> 16, (uint8_t) w1 >> 8, (uint8_t) w1,
        (uint8_t) w2 >> 24, (uint8_t) w2 >> 16, (uint8_t) w2 >> 8, (uint8_t) w2,
        (uint8_t) w3 >> 24, (uint8_t) w3 >> 16, (uint8_t) w3 >> 8, (uint8_t) w3,
        (uint8_t) w4 >> 24, (uint8_t) w4 >> 16, (uint8_t) w4 >> 8, (uint8_t) w4,
    };
}



/*AES_Key_Scheduler declarations*/
AES_Key_Scheduler::AES_Key_Scheduler(AES_key_t key){
    std::visit(
        [this](auto &&args){
            using T = std::decay_t<decltype(args)>;
            if constexpr( std::is_same_v<T,AES_128_key> ){
                this->n_key_words = 4; //4 * 32 = 128
                this->n_rounds = 11;
                AES_128_key true_key = args;
                /*Generate the round constants*/
                for(int i = 0; i < n_rounds; i++){
                    AES::AES_Round_Constants_function(i,this->rcon);    
                }
                /*Now get the keys*/
                uint32_t u32_round_keys[4*(this->n_rounds)] = {0U};
                for(int i = 0; i < 4*(this->n_rounds); i++){
                    AES::AES128_Key_Scheduler_function(i,true_key,u32_round_keys,this->rcon);
                }
                /*Now cast the keys*/
                for(int i = 0; i < this->n_rounds; i++){
                    this->_round_keys[i] = fromui32ToAES_128(u32_round_keys+4*i);
                }

            }else if constexpr( std::is_same_v<T,AES_192_key> ){
                this->n_key_words = 6;
                this->n_rounds = 13;

                AES_192_key true_key = args; 
                /*Generate the round constants*/
                for(int i = 0; i < n_rounds; i++){
                    AES::AES_Round_Constants_function(i,this->rcon);    
                }
                /*Now get the keys*/
                uint32_t u32_round_keys[4* (this->n_rounds)] = {0};
                for(int i = 0; i < 4*(this->n_rounds); i++){
                    AES::AES192_Key_Scheduler_function(i,true_key,u32_round_keys,this->rcon);
                }
                /*Now cast the keys*/
                for(int i = 0; i < this->n_rounds; i++){
                    this->_round_keys[i] = fromui32ToAES_128(u32_round_keys+4*i);
                }


            }else if constexpr( std::is_same_v<T,AES_256_key> ){
                this->n_key_words = 8;
                this->n_rounds = 15;

                AES_256_key true_key = args; 
                /*Generate the round constants*/
                for(int i = 0; i < n_rounds; i++){
                    AES::AES_Round_Constants_function(i,this->rcon);    
                }
                /*Now get the keys*/
                uint32_t u32_round_keys[4* (this->n_rounds)] = {0};
                for(int i = 0; i < 4*(this->n_rounds); i++){
                    AES::AES256_Key_Scheduler_function(i,true_key,u32_round_keys,this->rcon);
                }
                /*Now cast the keys*/
                for(int i = 0; i < this->n_rounds; i++){
                    this->_round_keys[i] = fromui32ToAES_128(u32_round_keys+4*i);
                }

            }else{
                throw AESException("AES_Key_Scheduler : AES_key_t type not recognized");
            }

        },
        key
    );

}

AES_128_key AES_Key_Scheduler::next(){
    AES_128_key result = this->_round_keys[currIndex];
    currIndex+=1;
    currIndex%=n_rounds;
    return result;
}

/*AES Cipher declarations*/


AES_Cipher::AES_Cipher(AES_key_t key) : sched(key){
    this->key = key;
    /*All inverses are needed to be computed, if they aren't*/
    if(AES::inverses[0x01] != 0x01){ //we'll use this as a sanity check
        for(uint8_t i = 0U ; i < 255U; i++){
            AES::inverses[i] = AES::computeInverse(i);
        }
    }
}


AES_state_t AES_Cipher::_AddRoundKey(AES_state_t prev_state, AES_128_key round_key){
    AES_state_t new_state = {0};
    for(int i = 0; i < 4; i++){
        new_state[i] = prev_state[i] ^ (
            (round_key[4*i] << 24) | 
            (round_key[4*i+1] << 16 )| 
            (round_key[4*i+2] << 8) | 
            (round_key[4*i+3])
        );
    }
    return new_state;
}

AES_state_t AES_Cipher::_SubBytes(AES_state_t prev_state){
    AES_state_t new_state = AES_state_t();
    for(int i = 0; i < 4; i++){
        new_state[i] = (uint32_t) (
            AES::S_Box( (uint8_t) prev_state[i] >> 24) << 24 |
            AES::S_Box( (uint8_t) prev_state[i] >> 16) << 16 |
            AES::S_Box( (uint8_t) prev_state[i] >> 8 ) << 8 |
            AES::S_Box( (uint8_t) prev_state[i] )
        );
    }
    return new_state;
}   

AES_state_t AES_Cipher::_ShiftRows(AES_state_t prev_state){
    AES_state_t new_state = {0};
    for(int i = 8; i <=24; i+=8){
        uint8_t b[] = { ( uint8_t ) prev_state[0] >> 24-i, 
             ( uint8_t ) prev_state[1] >> 24-i,
             ( uint8_t ) prev_state[2] >> 24-i,
             ( uint8_t ) prev_state[3] >> 24-i};
        int shift_amount = i/8;
        new_state[0] = b[(0+shift_amount)%4];
        new_state[1] = b[(1+shift_amount)%4];
        new_state[2] = b[(2+shift_amount)%4];
        new_state[3] = b[(3+shift_amount)%4];
    }
    return new_state;
}


AES_state_t AES_Cipher::_MixColumns(AES_state_t prev_state){
    AES_state_t new_state = {0};
    for(int i = 0; i < 4; i++){
        uint8_t b0 = (uint8_t)(prev_state[i] >> 24) ,
            b1 = (uint8_t)(prev_state[i] >> 16),
            b2 = (uint8_t)(prev_state[i] >> 8),
            b3 = (uint8_t)(prev_state[i]);
        uint8_t t = b0^b1^b2^b3;
        new_state[i] = 
            (b0 ^ t ^ AES::xtime( b0 ^ b1)) << 24 |
            (b1 ^ t ^ AES::xtime( b1 ^ b2)) << 16 |
            (b2 ^ t ^ AES::xtime( b2 ^ b3)) << 8 |
            (b3 ^ t ^ AES::xtime( b3 ^ b0))  ;
    }
    return new_state;
}

std::string AES_Cipher::cipher(std::string plaintext){
    /*first we should convert the plaintext to a valid state */
    AES_state_t state = {0};
    for(int i = 0; i < 4; i++){
        state[i] = plaintext[4*i] << 24 | plaintext[4*i+1] << 16 | plaintext[4*i+2] << 8 | plaintext[4*i+3];
    }
    /*now the cipher starts*/
    state = _AddRoundKey(state,this->sched.next());
    /*R-2 rounds*/
    for(int i = 1 ; i < this->sched.n_rounds-1; i++){
        state = _AddRoundKey(_MixColumns(_ShiftRows(_SubBytes(state))),this->sched.next());
    }
    /*last round*/
    state = _AddRoundKey(_ShiftRows(_SubBytes(state)),this->sched.next());
    /*convert state to string*/
    std::string s;
    for(int i = 0; i < 4; i++){
        s.push_back((uint8_t)(state[i] >> 24));
        s.push_back((uint8_t)(state[i] >> 16));
        s.push_back((uint8_t)(state[i] >> 8));
        s.push_back((uint8_t)(state[i] >> 24));
    }
    return s;
}

/*AESException declarations*/
AESException::AESException(){
    this->msg = "";
}

AESException::AESException(const char* msg) : msg(msg){}

const char* AESException::what() const noexcept{
    return this->msg;
};