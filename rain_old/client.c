#ifdef _WIN32
#include <Windows.h>
#else
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <openssl/aes.h>
#include <openssl/rand.h> 
#endif

/*
 *  client.c
 *  - Server generates clients with unique id and public key, maintains key associations. tbd on openssl library dependance, key format, etc.
 *
 *  - Client uses public key to encrypt data into file, send to server.
 *  - Server able to send cmds, rshell to client.
 *  - Obfuscate code and signatures.
 *  gcc -lssl -lcrypto
 * */

void error(const char *msg)
{
    perror(msg);
    exit(0);
}

/* send hash and data */
void cback() 
{
    int a = 10;
    printf("%i", a);
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
    int keylength;
    printf("Give a key length [only 128 or 192 or 256!]:\n");
    scanf("%d", &keylength);

    /* generate a key with a given length */
    unsigned char aes_key[keylength/8];
    memset(aes_key, 0, keylength/8);
    if (!RAND_bytes(aes_key, keylength/8))
        exit(-1);

    size_t inputslength = 0;
    printf("Give an input's length:\n");
    scanf("%lu", &inputslength);

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

    AES_set_decrypt_key(aes_key, keylength, &dec_key);
    AES_cbc_encrypt(enc_out, dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);

    /*printf("original:\t");
    hex_print(aes_input, sizeof(aes_input));

    printf("encrypt:\t");
    hex_print(enc_out, sizeof(enc_out));

    printf("decrypt:\t");
    hex_print(dec_out, sizeof(dec_out));*/
    
    if (!moo1 || buffersize<1)
        return;
    else
    {
        strncpy(moo1, enc_out, buffersize-1);
    }
    moo1[buffersize-1] = '\0';

}

int main(int argc, char *argv[])
{
    int sockfd, portno, n;
    struct sockaddr_in serv_addr;
    struct hostent *server;
    char buffer[256];

    if (argc < 3) {
       fprintf(stderr,"usage %s hostname port\n", argv[0]);
       exit(0);
    }

    portno = atoi(argv[2]);
    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    if (sockfd < 0) 
        error("ERROR opening socket");
    server = gethostbyname(argv[1]);

    if (server == NULL) {
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
        error("ERROR connecting");
    
    char moo2[256];
    try(moo2, sizeof(moo2));
    printf("encrypt:\t");
    hex_print(moo2, sizeof(moo2));
    

    /*printf("Please enter the message: ");
    bzero(buffer,256);
    fgets(buffer,255,stdin);
    n = write(sockfd,buffer,strlen(buffer));*/
    n = write(sockfd,moo2,strlen(moo2));

    if (n < 0) 
         error("ERROR writing to socket");

    /*bzero(buffer,256);
    n = read(sockfd,buffer,255);*/
    bzero(moo2, 256);
    n = read(sockfd, buffer, 255);

    if (n < 0) 
         error("ERROR reading from socket");

    /*printf("%s\n",buffer);*/
    printf("%s\n", moo2);
    close(sockfd);

    return 0;
}
