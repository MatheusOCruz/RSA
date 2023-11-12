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
    mpz_t p,q,phi;
    mpz_init(phi);
    gen_prime(p);
    gen_prime(q);

    mpz_mul(n,p,q);
    // para achar os fatores coprimos

    mpz_sub_ui(p,p,1);
    mpz_sub_ui(q,q,1);

    mpz_mul(phi,p,q); // numero de coprimos de n

    mpz_set_ui(e, 65537); // valor padrao



    mpz_clear(phi);
}

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
// RSA usando OAEP

void RSA_encrypt(){}


void oaep(){}




void unit_test_miller(){
    mpz_t t;
    mpz_init(t);
    int j = 0;
    //gmp_printf("%Zd\n",t);
    for (int i = 2; i < 1000; ++i) {
        mpz_set_ui(t, i);
        if (Miller_Rabin_test(t)){
            printf("%d ", i);
            j++;
        }
        if (j == 10) {
            printf("\n");
            j = 0;
        }

    }


}




int main() {

    //inicia a semente do rand
    srand(time(NULL));
    if (sodium_init() < 0) {
        // Falha na inicialização da biblioteca
        fprintf(stderr, "Erro na inicialização do libsodium\n");
        exit(EXIT_FAILURE);
    }

    u64 jonas[16] = {0x45D07A3D1C961A38,0x45D07A3D1C961A38,0x45D07A3D1C961A38,0x45D07A3D1C961A38,
                     0x45D07A3D1C961A38,0x45D07A3D1C961A38,0x45D07A3D1C961A38,0x45D07A3D1C961A38,
                     0x45D07A3D1C961A38,0x45D07A3D1C961A38,0x45D07A3D1C961A38,0x45D07A3D1C961A38,
                     0x45D07A3D1C961A38,0x45D07A3D1C961A38,0x45D07A3D1C961A38,0x45D07A3D1C961A38};
    mpz_t e,d,n;
    mpz_inits(e,d,n,NULL);
    RSA_init_keys(e, d, n);
    u8 digest[64];
    char* file_path = "/home/matheus/CLionProjects/RSA/teste.txt";
    hash_file_sha3(file_path, digest);
    for (int i = 0; i < 64; ++i) {
        printf("%02x",digest[i]);
    }






    return 0;
}
