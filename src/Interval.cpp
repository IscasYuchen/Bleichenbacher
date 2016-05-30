//============================================================================
// Name        :Interval.cpp
// Author      : YuchenWang
// Version     : 0.0.1
// Description : The interval class source file
//============================================================================
#include "Interval.h"

Interval::Interval() {
	down_bound  = BN_new();
	up_bound = BN_new();
}

Interval::Interval(BIGNUM *B){
	down_bound = BN_dup(B);
	up_bound = BN_dup(B);
	BN_mul_word(down_bound,2);
	BN_mul_word(up_bound,3);
	BN_sub_word(up_bound,1);
}

Interval::Interval(BIGNUM *a,BIGNUM *b){
	if(BN_cmp(b,a)<0)
		throw runtime_error("You shouldn't set the interval's up bound < down  bound");
	down_bound = BN_dup(a);
	up_bound = BN_dup(b);
}

Interval::~Interval() {
	if(down_bound != NULL)
		BN_free(down_bound);
	if(up_bound != NULL)
		BN_free(up_bound);
}

int Interval::Interval_set_bound(BIGNUM *a,BIGNUM *b){
	int ret = 1;
	if(down_bound  != NULL && a != NULL){
		BN_free(down_bound);
		down_bound = BN_dup(a);
	}
	if(up_bound != NULL && b != NULL){
		BN_free(up_bound);
		up_bound  = BN_dup(b);
	}
	return ret;
}

Interval & Interval::operator=(const Interval & interval){
	if(this == &interval)
		return *this;
	if(down_bound != NULL)
		BN_free(down_bound);
	down_bound	= BN_dup(interval.down_bound);
	if(up_bound != NULL)
		BN_free(up_bound);
	up_bound = BN_dup(interval.up_bound);
	return *this;
}

int Interval::Interval_update_bound(BIGNUM *a,BIGNUM *b){
	int ret = 1;

	if(down_bound == NULL || up_bound  == NULL)
		throw runtime_error("The interval is not perfect");
	if(a!=NULL && BN_cmp(a,down_bound)>0){
		BN_free(down_bound);
		BN_dup(a);
	}
	if(b!=NULL && BN_cmp(b,up_bound)<0){
		BN_free(up_bound);
		BN_dup(b);
	}

	return ret;
}

void Interval::Interval_get_bound(BIGNUM *a,BIGNUM*b){
	if(down_bound == NULL || up_bound == NULL)
		throw runtime_error("No value to give a and b");
	if(a == NULL || b == NULL)
		throw runtime_error("a and b must be allocated a memory");
	BN_copy(a,down_bound);
	BN_copy(b,up_bound);
}

BIGNUM* Interval::Interval_Size(){
	BIGNUM *ret = BN_new();
	BN_sub(ret,up_bound,down_bound);
	BN_add_word(ret,1);
	return ret;
}
