// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <stdio.h>
#include "tls_client_u.h"
//Socket supporting libraries
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include <cctype>


#define FAIL -1

char buf[1024];
char reply[1024];

int OpenListener(int port)
{   
    int sd;
    struct sockaddr_in addr;

    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}

SSL_CTX* InitServerCTX(void)
{   
     const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
	perror("Unable to create SSL context");
	ERR_print_errors_fp(stderr);
	exit(EXIT_FAILURE);
    }

    return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
    printf("Certificates loaded\n");
}

void ShowCerts(SSL* ssl)
{   
    X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No client certificates.\n");
}

char *Servlet(SSL* ssl) /* Serve the connection -- threadable */
{   
    int sd, bytes;
    const char* HTMLecho="";

    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            sprintf(reply, HTMLecho, buf);   /* construct reply */
            SSL_write(ssl, reply, strlen(reply)); /* send reply */
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}


oe_enclave_t* create_enclave(const char* enclave_path)
{
    oe_enclave_t* enclave = NULL;

    printf("Host: Enclave library %s\n", enclave_path);
    oe_result_t result = oe_create_tls_client_enclave(
        enclave_path,
        OE_ENCLAVE_TYPE_SGX,
        OE_ENCLAVE_FLAG_DEBUG,
        NULL,
        0,
        &enclave);

    if (result != OE_OK)
    {
        printf(
            "Host: oe_create_remoteattestation_enclave failed. %s",
            oe_result_str(result));
    }
    else
    {
        printf("Host: Enclave successfully created.\n");
    }
    return enclave;
}

void terminate_enclave(oe_enclave_t* enclave)
{
    oe_terminate_enclave(enclave);
    printf("Host: Enclave successfully terminated.\n");
}

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;
    uint8_t* encrypted_msg = NULL;
    size_t encrypted_msg_size = 0;
    oe_result_t result = OE_OK;
    int ret = 1;
    uint8_t* pem_key = NULL;
    size_t pem_key_size = 0;
    uint8_t* remote_report = NULL;
    size_t remote_report_size = 0;
    char* server_name = NULL;
    char* server_port = NULL;
    char  first_arg[50];
    char  second_arg[50];
    /* Check argument count */
    if (argc != 4)
    {
    print_usage:
        printf(
            "Usage: %s TLS_SERVER_ENCLAVE_PATH -server:<name> -port:<port>\n",
            argv[0]);
        return 1;
    }
    // read server name  parameter
    {
        const char* option = "-server:";
        int param_len = 0;
        param_len = strlen(option);
        if (strncmp(argv[2], option, param_len) == 0)
        {
            server_name = (char*)(argv[2] + param_len);
        }
        else
        {
            fprintf(stderr, "Unknown option %s\n", argv[2]);
            goto print_usage;
        }
    }

    // read port parameter
    {
        const char* option = "-port:";
        int param_len = 0;
        param_len = strlen(option);
        if (strncmp(argv[3], option, param_len) == 0)
        {
            server_port = (char*)(argv[3] + param_len);
        }
        else
        {
            fprintf(stderr, "Unknown option %s\n", argv[2]);
            goto print_usage;
        }
    }

    printf("Host: Creating the enclave\n");
    enclave = create_enclave(argv[1]);
    if (enclave == NULL)
    {
        goto exit;
    }

   
    printf("Opening tls server");
    SSL_CTX *ctx;
    int server;
    SSL_library_init();
    int call;
    ctx = InitServerCTX();        
    /* initialize SSL */
    LoadCertificates(ctx, "/home/vincenzo/Scrivania/FUNZIONANTE/mycert2.pem", "/home/vincenzo/Scrivania/FUNZIONANTE/mycert2.pem"); 
    server = OpenListener(atoi("8989"));    /* create server socket */


    while (1){   
	first_arg[50] = {};
	second_arg[50] = {};
	struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept */

        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
	int sd, bytes;
    	const char* HTMLecho="";

    	if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        	ERR_print_errors_fp(stderr);
    	else
    	{
        	ShowCerts(ssl);        /* get any certificates */
        	bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        	if ( bytes > 0 )
        	{
            		buf[bytes] = 0;
            		printf("Client msg: \"%s\"\n", buf);

        		ret = launch_tls_client(enclave, &call, (char*)buf, (char*)"8443");
				
			if (call  == 50)
        		{
            			HTMLecho = "NO";
        		}
			
			if(call == 0)
				HTMLecho = "SI";
	
			
            		sprintf(reply, HTMLecho, buf);   /* construct reply */
            		SSL_write(ssl, reply, strlen(reply)); /* send reply */
        	}
        	else
            		ERR_print_errors_fp(stderr);
    	}
    	sd = SSL_get_fd(ssl);       /* get socket connection */
    	SSL_free(ssl);         /* release SSL state */
    	close(sd);          /* close connection */
        printf("Buf: %s\n", buf);
	

        printf("Host: launch TLS client to initiate TLS connection\n");

        ret = 0;
    }  
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */ 
    /************************/
    
exit:

    if (enclave)
        terminate_enclave(enclave);

    printf("Host:  %s \n", (ret == 0) ? "succeeded" : "failed");
    return ret;
}
