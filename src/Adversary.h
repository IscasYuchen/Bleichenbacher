//============================================================================
// Name        : Adversary.h
// Author      : YuchenWang
// Version     : 0.0.2
// Description : The bleichenbacher adversary header file
//============================================================================


#ifndef ADVERSARY_H_
#define ADVERSARY_H_

#include "def.h"
#include "IntervalSet.h"

int  Adversary_start_connect(int port);


class Adversary {
private:
	RSA *pub_key;
	BIGNUM *C;
	BIGNUM *B;
	BIGNUM *B2;//2B
	BIGNUM *B3;//3B-1
	BIGNUM *s;
	IntervalSet *set;
	//the total query times
	int total_query;
	//calculate the c to be queried in oracle, by the current c and s
	//c1 needed to allocate a memory
	int calculate_query(BIGNUM *c1);
public:
	Adversary();
	Adversary(char *path,char *plaintext,int plaintext_length);
	~Adversary();
	//step 2 a~c return the number of oracle query
	//mode: 1,2,3 represents a,b,c
	int Adversary_Step2(int port,char mode);
	//step  3 will not provide any return value
	void Adversary_Step3();
	int Adversary_Step4();
	//include the different steps
	int Adversary_Attack(int port);
	int Adversary_Query(int &query_fd);
};

#endif /* ADVERSARY_H_ */
