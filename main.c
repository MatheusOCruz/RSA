#include <stdio.h>
#include <gmp.h>
#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include <openssl/evp.h>
#include <math.h>
#include <unistd.h>


#define true  1
#define false 0

#define BUFSIZE 1024

typedef uint8_t u8;
typedef uint32_t u32;
typedef uint64_t u64;



// geracao e teste de primos de 1024 bits

int Miller_Rabin_test(mpz_t prime_canditate){
    // n-1 = 2^k*r
    if (mpz_cmp_ui(prime_canditate, 2) == 0 | mpz_cmp_ui(prime_canditate, 3) == 0){
        return true;
    }
    mpz_t r, results, p_sub1;
    mpz_inits(results, p_sub1, NULL);
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
    u8 a_gen[128];
    mpz_t a;
    mpz_init(a);
    for (int i = 0; i <40; ++i) {
        randombytes(a_gen,128);
        mpz_import(a,128,1,1,0,0,a_gen);
        mpz_sub_ui (results,prime_canditate,3); // a entre 2 e p-2 -> (a mod p-3) + 2
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
    return true;
}

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


void sha3(u8 *message, u8 *digest){
    const EVP_MD *md = EVP_sha3_512();
    unsigned int hash_len;
    EVP_Digest(message, sizeof(message), digest, &hash_len, md, NULL);
}

void sha3_file(char *file_path, u8 *digest){
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

void MGF(u8* seed, u8* mask,int len, int seedLen){

    u8 seed_concat[seedLen + 4];
    u8 digest[64];
    memcpy(seed_concat,seed, seedLen);

    int i,j;
    for ( i = 0; i < ceil(len/64); ++i) {
        for (j = 0; j < 4; j++) {
            seed_concat[seedLen + j] = (i >> ((3 - j) * 8)) & 0xFF;
        }
        sha3(seed_concat,digest);
        memcpy(mask + (i*64),digest, 64);
    }
    if (i*64 != len) {
        for (j = 0; j < 4; j++) {
            seed_concat[seedLen + j] = (i >> ((3 - j) * 8)) & 0xFF;
        }
        sha3(seed_concat,digest);
        memcpy(mask + (i*64),digest, len-i*64);
    }

}


//#################################################

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
    u8 Phash[hash_len]; //hash do parametro de seguranca
    sha3(Parameter, Phash);
    u8 DB[hash_len + PS_len + 1 + mLen]; // phash || PS ||01 || M
    memcpy(DB, Phash, hash_len);
    memcpy(DB + hash_len, PS, PS_len);
    DB[hash_len+PS_len] = 0x01; // separador do padding
    memcpy(DB+hash_len+PS_len+1, M, mLen);

    u8 seed[hash_len]; randombytes(seed, hash_len); //gera seed
    //gera DB = DB masked
    u8 dbMask[emLen - hash_len];
    MGF(seed, dbMask, emLen - hash_len, hash_len); // Db mask
    for (int i = 0; i < (emLen - hash_len); ++i) DB[i]^=dbMask[i]; // DB = masked DB
    u8 seedMask[hash_len]; MGF(DB, seedMask, hash_len, hash_len); // seed mask
    for (int i = 0; i < hash_len; ++i) seed[i] ^= seedMask[i]; // seed = masked seed
    // EM = masked seed || masked DB
    memcpy(EM,seed, hash_len);
    memcpy(EM+hash_len, DB, emLen - hash_len);

}

u8* RSA_OAEP_encrypt(char *message ,mpz_t n, mpz_t e, u8* parameter, size_t *count){
    mpz_t c;
    mpz_init(c);
    u8 enc_message[224];
    OAEP_encode(message, enc_message, parameter,224);
    mpz_import(c,224,1,1,0,0,enc_message);
    mpz_powm(c,c,e,n);
    return (u8 *) mpz_export(NULL,count, 1,1,0,0,c);

}

// ###############################################

// len em >= 2hlen+1 -> 123


u8* OAEP_decode(const char *EM,  u8 *Parameter){
    size_t emLen = 224;
    const size_t hash_len = 64; //sha-3 512
    size_t db_len = emLen-hash_len;
    if (emLen <= hash_len + 1) printf("decoding error: size\n");
    u8 maskedSeed[hash_len], maskedDB[db_len];
    memcpy(maskedSeed,EM, hash_len);
    memcpy(maskedDB,EM+hash_len, emLen-hash_len);
    u8 seedMask[hash_len], dbMask[db_len];
    MGF(maskedDB,seedMask,hash_len, db_len);
    for (int i = 0; i < hash_len; ++i) maskedSeed[i] ^= seedMask[i]; // restaura a seed
    // restaura DB
    MGF(maskedSeed, dbMask,db_len, hash_len);
    for (int i = 0; i < db_len; ++i) maskedDB[i] ^= dbMask[i];     // restaura DB
    u8 Phash[hash_len]; sha3(Parameter, Phash);
    // DB PARTS phash || PS ||01 || M
    // checa de se o Phash ta igual
    for (int i = 0; i < hash_len; ++i) {
        if (maskedDB[i] != Phash[i] ){
            printf("decoding error: Phash\n ");
            return NULL;
        }
    }  //mesmo phash, agr e pra achar o comeco da msg
    int m_start = 0;
    for (int i = hash_len; i < db_len; ++i) {
        if (maskedDB[i] == 0x01) {
            m_start = i+1;
            break;
        }
        else if(maskedDB[i] != 0x00){
            printf("decoding error: PS\n");
            return NULL;
        }
    }
    size_t mLen = db_len - m_start;
    u8 *message = malloc(mLen);
    memcpy(message, maskedDB+m_start, mLen);
    return message;
}

u8* RSA_OAEP_decrypt(u8 *ciphertext, mpz_t n, mpz_t d, u8* Parameter, size_t count_cipher){
    mpz_t c;
    mpz_init(c);

    mpz_import(c,count_cipher, 1, 1, 0, 0, ciphertext);
    mpz_powm(c,c,d,n);

    size_t count;
    u8 *message = (u8 *) mpz_export(NULL, &count, 1,1,0,0,c);

// export do M para message
    return OAEP_decode(message, Parameter);

}

//################################################



//##################################################
// base64


char* BASE64_encode(char* input, size_t input_size, size_t *output_size){
    static char encoding_table[] = {
            'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
            'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
            'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
            'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
            'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
            'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
            'w', 'x', 'y', 'z', '0', '1', '2', '3',
            '4', '5', '6', '7', '8', '9', '+', '/'};

    static int reboco[] = {0,2,1};

    *output_size = (input_size + 2)/3 *4;
    char *output = malloc(*output_size);
    u32 a,b,c;
    for (size_t i = 0, j = 0; i < input_size;) {
         a = i < input_size ? (u8)input[i++] : 0;
         b = i < input_size ? (u8)input[i++] : 0;
         c = i < input_size ? (u8)input[i++] : 0;

        u32 tripla = a << 16 | b << 8 | c;

        output[j++] = encoding_table[(tripla >> 3 * 6) & 0x3F];
        output[j++] = encoding_table[(tripla >> 2 * 6) & 0x3F];
        output[j++] = encoding_table[(tripla >> 1 * 6) & 0x3F];
        output[j++] = encoding_table[(tripla >> 0 * 6) & 0x3F];
    }
    for (int i = 0; i < reboco[input_size % 3]; i++)
        output[*output_size - 1 - i] = '=';
    return output;
}

char* BASE64_decode(char* input, size_t input_size, size_t *output_size){
    const u32 B64_decoder[256] = { // so pra n ter q converter no shift , memoria q lute
            0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,
            0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0, 62, 63, 62, 62, 63, 52, 53, 54, 55,
            56, 57, 58, 59, 60, 61,  0,  0,  0,  0,  0,  0,  0,  0,  1,  2,  3,  4,  5,  6,
            7,  8,  9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,  0,
            0,  0,  0, 63,  0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
            41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };
    u32 pad = input_size > 0 && (input_size % 4 || input[input_size-1] == '=');
    size_t len = ((input_size + 3)/ 4 - pad) * 4;
    *output_size = len/4 * 3 + pad;
    char* output = malloc(*output_size);
    for (size_t i = 0, j = 0; i < len;) {
        u32 n = B64_decoder[input[i++]] << 18 |
                B64_decoder[input[i++]] << 12 |
                B64_decoder[input[i++]] << 6 |
                B64_decoder[input[i++]];
        output[j++] = n >> 16;
        output[j++] = n >> 8 & 0xFF;
        output[j++] = n & 0xFF;
    }
    if (pad){
        int n = B64_decoder[input[len]] << 18 | B64_decoder[input[len + 1]] << 12;
        output[(int)*output_size - 1] = n >> 16;
        if (input_size > len + 2 && input[len + 2] != '='){
            n |= B64_decoder[input[len + 2]] << 6;
            output = (char*) realloc(output, (int)*output_size + 1);
            *output_size += 1;
            output[(int)*output_size -1] = n >> 8 & 0xff;
        }
    }
    return output;
}

// ################################################


// assinatura e verificacao de assinatura RSA

u8* RSA_sign(char *file_path, mpz_t n, mpz_t d){
    mpz_t t;
    mpz_init(t);
    u8 digest[64];
    sha3_file(file_path, digest);
    mpz_import(t,64,1,1,0,0,digest);
    // n sei oq seria o parametro ent na duvida vai uns 0
    u8 parameter[64];
    memset(parameter, 0, 64);
    size_t ciphertext_len;
    u8* ciphertext = RSA_OAEP_encrypt(digest,n,d,parameter,&ciphertext_len);
    u8 *full_msg = malloc(sizeof(ciphertext_len) + ciphertext_len);
    memcpy(full_msg, &ciphertext_len, sizeof(ciphertext_len));
    memcpy(full_msg+sizeof(ciphertext_len), ciphertext, ciphertext_len);
    size_t message_size;
    char *encoded_message = BASE64_encode(full_msg, ciphertext_len+ sizeof(ciphertext_len), &message_size);
    u8* full_encoded = malloc(message_size + sizeof(message_size));
    memcpy(full_encoded, &message_size, sizeof(message_size));
    memcpy(full_encoded+ sizeof(message_size), encoded_message, message_size);
    return full_encoded;

}

int RSA_verify(char* file_path,u8* full_msg, mpz_t n, mpz_t e){
    size_t message_len;
    memcpy(&message_len, full_msg, sizeof(message_len));
    char encoded_ciphertext[message_len];
    memcpy(encoded_ciphertext, full_msg + sizeof(message_len),message_len);
    char* decoded_ciphertext = BASE64_decode(encoded_ciphertext, message_len, & message_len);
    size_t ciphertext_len;
    memcpy(&ciphertext_len, decoded_ciphertext, sizeof(ciphertext_len));
    u8 ciphertext[ciphertext_len];
    memcpy(ciphertext, decoded_ciphertext + sizeof(ciphertext_len),ciphertext_len);
    u8 Parameter[64];
    memset(Parameter, 0, 64);
    u8 *received_hash = RSA_OAEP_decrypt(ciphertext, n, e, Parameter, ciphertext_len);
    u8 hash[64];
    sha3_file(file_path, hash);
    for (int i = 0; i < 64; ++i) {
        if (hash[i] != received_hash[i]){
            printf("tem uma cobra na minha bota!\n");
            free(received_hash);
            return false;
        }
    }
    free(received_hash);
    return true;
}

// ##################################################



int main() {

    if (sodium_init() < 0) {
        // Falha na inicialização da biblioteca
        printf("Erro na inicialização do libsodium\n");
        exit(EXIT_FAILURE);
    } // gerador de numero aleatorio

    // chave privada = (d, n) chave publica = (e, n)
    mpz_t e,d,n;
    mpz_inits(e,d,n, NULL);
    RSA_init_keys(e, d, n);



//    char file_path[PATH_MAX];
//    getcwd(file_path, sizeof(file_path));
//    strcat(file_path,"/");
//
//    printf("insira o nome do arquivo:");
//    char file_name[50];
//    fgets(file_name, sizeof(file_name), stdin);
//    size_t len = strlen(file_name);
//    if (len > 0 && file_name[len - 1] == '\n') {
//        file_name[len - 1] = '\0';
//    }
//    strcat(file_path,file_name);

    gmp_printf("chaves geradas,\n n:%Zx\ne:%Zx\nd:%Zx\n",n,e,d);
    printf("chave publica : (e,n)\nchave privada: (d,n)\n");

    char* file_path = "/home/matheus/CLionProjects/RSA/teste.txt";
    u8* sign = RSA_sign(file_path, n,d); // assina com chave privada (d,n)
    size_t message_len;
    memcpy(&message_len, sign, sizeof(message_len));
    printf("assinatura gerada para o arquivo:");
    for (int i = 0; i < (int)(message_len+ sizeof(message_len)); ++i) {
        printf("%x",sign[i]);
    }
    printf("\n");

    if (RSA_verify(file_path, sign, n, e)) printf("assinatura verificada\n");


    return 0;
}
