#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sodium.h>
#include "AES.h"
#include <openssl/evp.h>

#define true  1
#define false 0

#define BUFSIZE 1024

typedef uint8_t u8;
typedef uint64_t u64;



// geracao e teste de primos de 1024 bits

int Miller_Rabin_test(mpz_t prime_canditate){
    // n-1 = 2^k*r

    if (mpz_cmp_ui(prime_canditate, 2) == 0 | mpz_cmp_ui(prime_canditate, 3) == 0){
        // numero nunca deve ser tao pequeno, mas e um caso possivel ne ent fazer oq
        return true;
    }
    mpz_t r, results, p_sub1;

    mpz_inits(results, p_sub1, NULL);

    // provavel q possa remover (garantir q numero nao e par na criacao)
    mpz_mod_ui(results,prime_canditate,2);
    if (mpz_cmp_ui(results,0) == 0) {

        mpz_clear(results);
        mpz_clear(p_sub1);

        return false; // numero e par
    }

    mpz_sub_ui(p_sub1, prime_canditate, 1); // p-1
    mpz_init_set(r,p_sub1);


    int k = 0; // potencia de 2

    mpz_mod_ui(results, p_sub1, 2);

    while (mpz_cmp_ui(results, 0) == 0) { // while r mod 2 != 0
        k++;
        mpz_div_ui(r, r, 2);
        mpz_mod_ui(results, r, 2);
    }  // enquanto o numero for divisivel por 2


    // aqui temos k e r(p_sub1)

    // a quantidade de 'a' escolhido seria um parametro de seguranca
    // quanto mais vezes o teste e feito maior a prob (testar com 10 so)

    u8 a_gen[128];
    mpz_t a;
    mpz_init(a);

    for (int i = 0; i <5; ++i) {
        randombytes(a_gen,128);

        mpz_import(a,128,1,1,0,0,a_gen); // converte para o tipo magico

        // a entre 2 e p-2 -> (a mod p-3) + 2

        mpz_sub_ui (results,prime_canditate,3);
        mpz_mod(a,a,results);
        mpz_add_ui(a,a,2);  // a entre 2 e p-2

        mpz_powm(results,a,r,prime_canditate);  // a^r mod p

        if (mpz_cmp_ui(results,1) == 0) return 1; // a^p-1 mod n == 1

    // testar para 0 a n-1
        for (u64 j = 0; j < k; ++j) {
            // a ^ (2^j) * r
            mpz_ui_pow_ui(results, (u64)2, j);          // results = 2^j
            mpz_mul(results,results,r);                 //  results = 2^j * r
            mpz_powm(results,a,results,prime_canditate); // (a^(2^j * r) ) mod p
            if (mpz_cmp(results, p_sub1) == 0){
                break;
            }
            /*
             * se chegou ate o ultimo j sem o break ent
             * nao e congruente para nenhum valor de j
             * logo e um numero composto
             */
            if (j == k - 1) {
                mpz_clear(results);
                mpz_clear(p_sub1);
                mpz_clear(r);
                mpz_clear(a);

                return false;
            }




        }


    }

    //  se o numero nao der como composto em nenhum teste
    //  provavelmente primo
    mpz_clear(results);
    mpz_clear(p_sub1);
    mpz_clear(r);
    mpz_clear(a);

    return 1;
} // teoricamente funciona ??

void gen_prime(mpz_t prime) {
    u8 gen_buffer[128];
    while(true){
        randombytes(gen_buffer, 128);
        gen_buffer[127] |= 1; // garante que e um valor impar

        mpz_import(prime,128,1,1,0,0,gen_buffer);

        if (Miller_Rabin_test(prime)) break;
    }
} // gera um numero provavelmente primo

void RSA_init_keys(mpz_t e, mpz_t d, mpz_t n){
    mpz_t p,q,phi_n;
    mpz_inits(p,q,phi_n,NULL);
    gen_prime(p);
    gen_prime(q);

    mpz_mul(n,p,q);
    // para achar os fatores coprimos

    mpz_sub_ui(p,p,1);
    mpz_sub_ui(q,q,1);

    mpz_mul(phi_n,p,q); // numero de coprimos de n

    mpz_set_ui(e, 65537); // valor padrao

    mpz_invert(d,e,phi_n);

    if(mpz_cmp(d,e) == 0) mpz_add(d,d,phi_n); // chave publica nao pode ser igual a privada



    mpz_clear(phi_n);
}

// ###############################################

// RSA usando OAEP

// hashb -> sha3 hLen -> 512
// mlen <= emLen - 2hLen (1024) - 1 -> <=emLen - 1025



/*
 * gen PS
 * pHash = Hash(P)
 */
// funcoes auxiliares do treco
void sha3(u8 *message, u8 *digest){
    const EVP_MD *md = EVP_sha3_512();
    unsigned int hash_len;
    EVP_Digest(message, sizeof(message), digest, &hash_len, md, NULL);
}

void MGF(u8* seed, u8* mask,int len, int seedLen){
    printf("seed: ");
    for (int i = 0; i < seedLen; ++i) {
        printf("%x", seed[i]);
    }
    printf("\n");
    
    u8 seed_concat[seedLen + 4];
    u8 digest[64];
    memcpy(seed_concat,seed, seedLen);
    for (int i = 0; i < len/64; ++i) {
        for (int j = 0; j < 4; j++) {
            seed_concat[seedLen + j] = (i >> ((3 - j) * 8)) & 0xFF;
        }
        sha3(seed_concat,digest);
        memcpy(mask + (i*64),digest, 64);
    }
    printf("mask: ");
    for (int i = 0; i < len; ++i) {
        printf("%x", mask[i]);
    }
    printf("\n");
}

// talvez o parametro seja a chave do aes
// e a mensagem seja o trem criptografado pelo aes ???
// num seeeei!


//#################################################

// teoricamente o oaep ta pronto

void OAEP_encode(const char* M, char* EM, u8* Parameter, int emLen){

    size_t mLen = strlen(M);
    const size_t hash_len = 64; //sha-3 512
    size_t PS_len = emLen - (mLen + 2*hash_len + 1);

    // P pode ser de qualquer tamanho ja q sha-3 n tem problema com tamanho de input
    if (mLen > (emLen - 2*hash_len - 1) || PS_len <= 0 ) {
        printf("mensagem muito longa\n");
        return;
    }


    u8 PS[PS_len]; memset(PS,0,PS_len); //padding


    u8 Phash[hash_len];


    sha3(Parameter, Phash);

    printf("Phash:");
    for(int i = 0; i < hash_len; ++i) {
        printf("%x",Phash[i]);
    }

    printf("\n");


    u8 DB[hash_len + PS_len + 1 + mLen]; // phash || PS ||01 || M
    memcpy(DB, Phash, hash_len);
    memcpy(DB + hash_len, PS, PS_len);
    DB[hash_len+PS_len] = 0x01;
    memcpy(DB+hash_len+PS_len+1, M, mLen);

    //gera seed
    u8 seed[hash_len]; randombytes(seed, hash_len);

    //gera DB = DB masked
    u8 dbMask[emLen - hash_len]; MGF(seed, dbMask, emLen - hash_len, hash_len); // Db mask
    printf("DB enc:");
    for (int i = 0; i < emLen - hash_len; ++i) {
        printf("%x", DB[i]);
    }
    printf("\n");

    printf("DB mask:");
    for (int i = 0; i < emLen - hash_len; ++i) {
        printf("%x", dbMask[i]);
    }
    printf("\n");

    for (int i = 0; i < (emLen - hash_len); ++i) DB[i]^=dbMask[i]; // DB = masked DB
    printf("DB after mask:");
    for (int i = 0; i < emLen - hash_len; ++i) {
        printf("%x", DB[i]);
    }
    printf("\n");
    // seed = masked seed
    u8 seedMask[hash_len]; MGF(DB, seedMask, hash_len, hash_len); // seed mask

    printf("seed mask:");
    for (int i = 0; i < hash_len; ++i) {
        printf("%x",seedMask[i]);
    }
    printf("\n");

    for (int i = 0; i < hash_len; ++i) seed[i] ^= seedMask[i]; // seed = masked seed

    // EM = masked seed || masked DB

    memcpy(EM,seed, hash_len);
    memcpy(EM+hash_len, DB, emLen - hash_len);


}
void RSA_OAEP_encrypt(char *message, char*ciphertext ,mpz_t n, mpz_t e, u8* parameter){
    int k;
    char* enc_message;
    k = strlen(message) + 3072; // valor randon da vida
    OAEP_encode(message, enc_message, parameter,k-8); // -1 byte


    mpz_t m, c;
    mpz_inits(m,c,NULL);

    // converter EM para um numero m
    size_t str_len = strlen(enc_message);
    mpz_import(m, str_len, 1, 1, 0, 0, enc_message);

    mpz_powm(c, m, e, n); // C = rsa M (e,n)

    // c lenght <= 2048 bits ja q n <= 2048
    // padding em c para sempre ser 2048 bits
    // como padding e 0 ele vai pro beleleu quando virar numero pra voltar na funcao e da no mesmo eeeee
    // c -> ciphertext as number

    // mpz_export ... nao sei fazer esse trem ainda



    mpz_clear(m);
    // dps tem q dar um jeito em c tmb
} // pronta?

// ###############################################

//agora pra tentar o decrypt dessa joca
// len em >= 2hlen+1 -> 123


void OAEP_decode(const char *EM, u8 *Parameter){
    size_t emLen = 256;
    const size_t hash_len = 64; //sha-3 512
    size_t db_len = emLen-hash_len;
    if (emLen <= hash_len + 1) printf("decoding error: size\n");

    u8 maskedSeed[hash_len], maskedDB[db_len];
    memcpy(maskedSeed,EM, hash_len);
    memcpy(maskedDB,EM+hash_len, emLen-hash_len);


    printf("DB masked decode:");
    for (int i = 0; i < db_len; ++i) {
        printf("%x", maskedDB[i]);
    }
    printf("\n");


    u8 seedMask[hash_len], dbMask[db_len];
    // restaura seed
    MGF(maskedDB,seedMask,hash_len, db_len);

    printf("seed mask:");
    for (int i = 0; i < hash_len; ++i) {
        printf("%x",seedMask[i]);
    }
    printf("\n");

    for (int i = 0; i < hash_len; ++i) maskedSeed[i] ^= seedMask[i];

    // restaura DB
    MGF(maskedSeed, dbMask,db_len, hash_len);
    for (int i = 0; i < db_len; ++i) maskedDB[i] ^= dbMask[i];

    u8 Phash[hash_len]; sha3(Parameter, Phash);

    printf("Phash no decode:");
    for(int i = 0; i < hash_len; ++i) {
        printf("%x",Phash[i]);
    }

    printf("\n");

    // DB PARTS phash || PS ||01 || M

    // checa de se o Phash ta igual
    for (int i = 0; i < hash_len; ++i) {
        if (maskedDB[i] != Phash[i] ){
            printf("decoding error: Phash\n ");
            return;
        }
    }

    //mesmo phash, agr e pra achar o comeco da msg
    int m_start = 0;
    for (int i = hash_len; i < db_len; ++i) {
        if (maskedDB[i] == 0x01) {
            m_start = i+1;
            break;
        }
        else if(maskedDB[i] != 0x00){
            printf("decoding error: PS\n");
            return;
        }
    }
    size_t mLen = db_len - m_start;
    u8 message[mLen];
    memcpy(message, maskedDB+m_start, mLen);

    for (int i = 0; i < mLen; ++i) {
        printf("%c", message[i]);
    }




}
void RSA_OAEP_decrypt(char* ciphertext, char*message, mpz_t n, mpz_t d, u8* Parameter){

}



//################################################
void hash_file_sha3(char *file_path, u8 *digest){
    EVP_MD_CTX *mdctx;
    const EVP_MD *md;
    unsigned char buffer[BUFSIZE];
    size_t bytes_read;
    FILE *file;

    md = EVP_sha3_512();
    file = fopen(file_path, "rb");

    if(!file) {
        fprintf(stderr, "Error opening file\n");
        return;
    }
    mdctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(mdctx, md, NULL);
    while((bytes_read = fread(buffer, 1, BUFSIZE, file)) != 0)
        EVP_DigestUpdate(mdctx, buffer, bytes_read);

    EVP_DigestFinal_ex(mdctx, digest, NULL);
    EVP_MD_CTX_free(mdctx);

    fclose(file);
}




int main() {



    if (sodium_init() < 0) {
        // Falha na inicialização da biblioteca
        fprintf(stderr, "Erro na inicialização do libsodium\n");
        exit(EXIT_FAILURE);
    } // gerador de numero aleatorio

    // chave privada = (d, n) chave publica = (e, n)
    mpz_t e,d,n;
    mpz_inits(e,d,n,NULL);
    //RSA_init_keys(e, d, n);

    // teste com o valor 0x1234



    mpz_t teste;
    mpz_init(teste);


    /*
    printf("%d\n",mpz_sizeinbase(n,2));
    char* resultStr = mpz_get_str(NULL, 16, n);
    printf("%d", strlen(resultStr)*4);
    */



    // calculo de hash de mensagem em claro
    u8 digest[64];
    char* file_path = "/home/matheus/CLionProjects/RSA/teste.txt";
    hash_file_sha3(file_path, digest);

    char aa[256];
    OAEP_encode("suco de fruta com tamarindo", aa, digest, 256);


    OAEP_decode(aa, digest);


    return 0;
}
