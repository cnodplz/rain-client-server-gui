#ifdef _WIN32
#include <Windows.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#endif

/*
 *  decrypter.c
 *  - Decrypts sysinfo, fix after function read.
 *  - Strip duplicate client code.
 *  build: gcc -lssl -lcrypto <file.c> -o <file.exe>
 * */

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

void handleErrors(void)
{
    ERR_print_errors_fp(stderr);
    abort();
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
    unsigned char *iv, unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *ctx;

    int len;
    int ciphertext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the encryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be encrypted, and obtain the encrypted output.
     * EVP_EncryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
    ciphertext_len = len;

    /* Finalize the encryption. Further ciphertext bytes may be written at
     * this stage.
     */
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
        ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
    unsigned char *iv, unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;

    int len;

    int plaintext_len;

    /* Create and initialise the context */
    if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

    /* Initialise the decryption operation. IMPORTANT - ensure you use a key
     * and IV size appropriate for your cipher
     * In this example we are using 256 bit AES (i.e. a 256 bit key). The
     * IV size for *most* modes is the same as the block size. For AES this
     * is 128 bits */
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();

    /* Provide the message to be decrypted, and obtain the plaintext output.
     * EVP_DecryptUpdate can be called multiple times if necessary
     */
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    /* Finalise the decryption. Further plaintext bytes may be written at
     * this stage.
     */
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
        plaintext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return plaintext_len;
}

/* send hash and data */
void cback() 
{
    int a = 10;
    printf("%i\n", a);
}

// a simple hex-print routine. could be modified to print 16 bytes-per-line
static void hex_print(const void* pv, size_t len)
{
    const unsigned char * p = (const unsigned char*)pv;
    if (NULL == pv)
        printf("NULL");
    else
    {
        size_t i = 0;
        for (; i<len;++i)
            printf("%02X ", *p++);
    }
    printf("\n");
}

void try(unsigned char* moo1, int buffersize)
{
    /*int keylength;
    printf("Give a key length [only 128 or 192 or 256!]:\n");
    scanf("%d", &keylength);*/
    int keylength = 256;

    /* generate a key with a given length */
    unsigned char aes_key[keylength/8];
    memset(aes_key, 0, keylength/8);
    if (!RAND_bytes(aes_key, keylength/8))
        exit(-1);

    /*size_t inputslength = 0;
    printf("Give an input's length:\n");
    scanf("%lu", &inputslength);*/
    size_t inputslength = 256;

    /* generate input with a given length */
    unsigned char aes_input[inputslength];
    memset(aes_input, 'X', inputslength);

    /* init vector */
    unsigned char iv_enc[AES_BLOCK_SIZE], iv_dec[AES_BLOCK_SIZE];
    RAND_bytes(iv_enc, AES_BLOCK_SIZE);
    memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);

    // buffers for encryption and decryption
    const size_t encslength = ((inputslength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    unsigned char enc_out[encslength];
    unsigned char dec_out[inputslength];
    memset(enc_out, 0, sizeof(enc_out));
    memset(dec_out, 0, sizeof(dec_out));

    // so i can do with this aes-cbc-128 aes-cbc-192 aes-cbc-256
    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(aes_key, keylength, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);
    hex_print(aes_key, sizeof(aes_key));

    AES_set_decrypt_key(aes_key, keylength, &dec_key);
    AES_cbc_encrypt(enc_out, dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);

    /*printf("original:\t");
    hex_print(aes_input, sizeof(aes_input));*/

    printf("encrypt:\t");
    hex_print(enc_out, sizeof(enc_out));

    /*printf("decrypt:\t");
    hex_print(dec_out, sizeof(dec_out));*/
    
    if (!moo1 || buffersize<1)
        return;
    else
    {
        strncpy(moo1, enc_out, buffersize-1);
    }
    moo1[buffersize-1] = '\0';

}

int sendo(int argc, char *argv[], unsigned char *ciphertext, int ciphertext_len)
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[256];
    if (argc < 3)
    {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }
    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0)
    {
        error("ERROR opening socket");
    }
    server = gethostbyname(argv[1]);
    if (server == NULL)
    {
        fprintf(stderr,"ERROR, no such host\n");
        exit(0);
    }
    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    bcopy((char *)server->h_addr, 
         (char *)&serv_addr.sin_addr.s_addr,
         server->h_length);
    serv_addr.sin_port = htons(portno);
    if (connect(sockfd,(struct sockaddr *) &serv_addr,sizeof(serv_addr)) < 0)
    {
        error("ERROR connecting");
    }
    /*char moo2[256];
    try(moo2, sizeof(moo2));
    printf("encrypt:\t");
    hex_print(moo2, sizeof(moo2));
    printf("sizeof moo2: %i", moo2);*/

    /*printf("Please enter the message: ");
    bzero(buffer,256);
    fgets(buffer,255,stdin);
    n = write(sockfd,buffer,strlen(buffer));*/
    //n = write(sockfd,moo2,strlen(moo2));
    n = write(sockfd, ciphertext, ciphertext_len);
    if (n < 0)
    { 
        error("ERROR writing to socket");
    } 
    /*bzero(buffer,256);
    n = read(sockfd,buffer,255);*/
    //bzero(ciphertext, 256);
    n = read(sockfd, buffer, 255);
    if (n < 0)
    {
        error("ERROR reading from socket");
    }
    /*printf("%s\n",buffer);*/
    hex_print(ciphertext, ciphertext_len);
    close(sockfd);
    return 0; 
}

int rancheck()
{
    int y = rand()%10;
    return y;
}

/*const char* pcszPassphrase = "mufasa";*/
const char* pcszPassphrase = "mufasa1";
static void gen_callback(int iWhat, int inPrime, void* pParam);
static void init_openssl(void);
static void cleanup_openssl(void);
static int passwd_callback(char *pcszBuff,int size,int rwflag, void *pPass);
static void handle_openssl_error(void);

int main(int argc, char *argv[])
{
    EVP_PKEY* pPrivKey = NULL;
    FILE* pFile = NULL;
    int iRet = EXIT_SUCCESS;
    init_openssl();
    /* Read the keys */
    EVP_PKEY_free(pPrivKey);
    pPrivKey = NULL;
    if((pFile = fopen("private_key.pem","rt")) && 
        (pPrivKey = PEM_read_PrivateKey(pFile,NULL,passwd_callback,(void*)pcszPassphrase)))
    {
        fprintf(stderr,"Private key read.\n");
    }
    else
    {
        fprintf(stderr,"Cannot read \"private_key.pem\".\n");
        handle_openssl_error();
        iRet = EXIT_FAILURE;
    }
    if(pFile)
    {
        fclose(pFile);
        pFile = NULL;
    }
    cleanup_openssl();

    /* Set up the key and iv. Do I need to say to not hard code these in a
     * real application? :-)
     */
    /* A 256 bit key */
    unsigned char *key = (unsigned char *)"01234567890123456789012345678901";
    /* A 128 bit IV */
    unsigned char *iv = (unsigned char *)"0123456789012345";

    /* Message to be encrypted */
    unsigned char *plaintext =
    (unsigned char *)"The quick brown fox jumps over the lazy dog";

    /* Buffer for ciphertext. Ensure the buffer is long enough for the
     * ciphertext which may be longer than the plaintext, dependant on the
     * algorithm and mode
     */
    unsigned char ciphertext[256];

    /* Buffer for the decrypted text */
    unsigned char decryptedtext[256];

    int decryptedtext_len, ciphertext_len;

    /* Encrypt the plaintext */
    ciphertext_len = encrypt(plaintext, strlen((char *)plaintext), key, iv,
    ciphertext);

    /* Do something useful with the ciphertext here */
    printf("Ciphertext is:\n");
    BIO_dump_fp(stdout, (const char *)ciphertext, ciphertext_len);

    /* Decrypt the ciphertext
    decryptedtext_len = decrypt(ciphertext, ciphertext_len, key, iv,
    decryptedtext);

    Add a NULL terminator. We are expecting printable text
    decryptedtext[decryptedtext_len] = '\0';

    printf("hex_print() ciphertext:\n");
    hex_print(ciphertext, ciphertext_len);

    Show the decrypted text
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);*/

    unsigned char ciph_buff[256];
    FILE *ciph_test;
    ciph_test = fopen("crypto", "rb");
    int bytez;
    bytez = fread(ciph_buff,sizeof(unsigned char),sizeof(ciph_buff),ciph_test);
    printf("bytez: %i", bytez);
    ciphertext_len = bytez;
    for (int i=0;i<255;i++)
        printf("%u ", ciph_buff[i]);
    printf("\n");

    /* Do something useful with the ciphertext here */
    printf("Cipherbuff is:\n");
    BIO_dump_fp(stdout, (const char *)ciph_buff, ciphertext_len);

    /* Decrypt the ciphertext */
    decryptedtext_len = decrypt(ciph_buff, ciphertext_len, key, iv,
    decryptedtext);
    /* Add a NULL terminator. We are expecting printable text */
    decryptedtext[decryptedtext_len] = '\0';
    printf("hex_print() ciphertext:\n");
    hex_print(ciph_buff, ciphertext_len);
    /* Show the decrypted text */
    printf("Decrypted text is:\n");
    printf("%s\n", decryptedtext);

    /*sleep until rand*/
    srand(time(NULL));
    int timing = 1;

    while(1)
    {
        if(rancheck() == 5)
        {
            /* Decrypt the ciphertext */
            decryptedtext_len = decrypt(ciph_buff, ciphertext_len, key, iv,
            decryptedtext);
            /* Add a NULL terminator. We are expecting printable text */
            decryptedtext[decryptedtext_len] = '\0';
            printf("hex_print() ciphertext:\n");
            hex_print(ciph_buff, ciphertext_len);
            /* Show the decrypted text */
            printf("Decrypted text :D is:\n");
            printf("%s\n", decryptedtext);
        }
        else
        {
            sleep(timing);
        }
    }
    return iRet;
}

void gen_callback(int iWhat, int inPrime, void* pParam)
{
    char c='*';
    switch(iWhat)
    {
        case 0: c = '.';  break;
        case 1: c = '+';  break;
        case 2: c = '*';  break;
        case 3: c = '\n'; break;
    }
    fprintf(stderr,"%c",c);
}

int passwd_callback(char *pcszBuff,int size,int rwflag, void *pPass)
{
    size_t unPass = strlen((char*)pPass);
    if(unPass > (size_t)size)
        unPass = (size_t)size;
    memcpy(pcszBuff, pPass, unPass);
    return (int)unPass;
}

void init_openssl(void)
{
    if(SSL_library_init())
    {
        SSL_load_error_strings();
        OpenSSL_add_all_algorithms();
        RAND_load_file("/dev/urandom", 1024);
    }
    else
        exit(EXIT_FAILURE);
}

void cleanup_openssl(void)
{
    CRYPTO_cleanup_all_ex_data();
    ERR_free_strings();
    ERR_remove_thread_state(0);
    EVP_cleanup();
}

void handle_openssl_error(void)
{
    ERR_print_errors_fp(stderr);
}
