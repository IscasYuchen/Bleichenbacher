//============================================================================
// Name        : def.h
// Author      : YuchenWang
// Version     : 0.0.1
// Description : Bleichenbacher attack program header file
//============================================================================

#ifndef DEF_H_
#define DEF_H_

#include <iostream>
#include <stdexcept>
#include <cstring>
#include <ctime>
#include <vector>
#include <list>
using namespace std;

#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include<openssl/ssl.h>
#include<openssl/rsa.h>
#include<openssl/bn.h>
#include<openssl/pem.h>
#include<openssl/err.h>

const int max_len = 1024;

# define n2s(c,s)        ((s=(((unsigned int)(c[0]))<< 8)| \
                            (((unsigned int)(c[1]))    )),c+=2)
# define s2n(s,c)        ((c[0]=(unsigned char)(((s)>> 8)&0xff), \
                          c[1]=(unsigned char)(((s)    )&0xff)),c+=2)

#endif /* DEF_H_ */
