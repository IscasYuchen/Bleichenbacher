//============================================================================
// Name        : Oracle.h
// Author      : YuchenWang
// Version     : 0.0.1
// Description : The bleichenbacher oracle header file
//============================================================================

#ifndef ORACLE_H_
#define ORACLE_H_

#include "def.h"

typedef bool (*oracle_engine)(RSA*,BIGNUM*);

bool Oracle_TTT(RSA *,BIGNUM*);

class Oracle {
private:
	//RSA private key
	RSA *priv_key;
	//The oracle launched
	bool (*engine)(RSA*,BIGNUM *c);
public:
	Oracle();
	Oracle(char *path,oracle_engine engine );
	virtual ~Oracle();
	friend int Oracle_start_listen(Oracle &oracle,int port);
};
//only verify that the decrypted message is strat with 0x00,0x02
int Oracle_start_listen(Oracle &oracle,int port);

#endif /* ORACLE_H_ */
