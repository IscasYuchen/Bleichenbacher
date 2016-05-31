//============================================================================
// Name        : IntervalSet.cpp
// Author      : YuchenWang
// Version     : 0.0.2
// Description : The Bleichenbacher IntervalSet source file
//============================================================================


#include "IntervalSet.h"

IntervalSet::IntervalSet() : set(){}

IntervalSet::IntervalSet(BIGNUM * B){
	Interval * b_interval = new Interval(B);
	set.push_back(b_interval);
}

//memories need to be deleted
IntervalSet::~IntervalSet() {
	set.clear();
}

int IntervalSet::IntervalSet_Num(){
	return set.size();
}

int IntervalSet::IntervalSet_Union(Interval *interval){
	int ret = 0;

	BIGNUM *down_bound = BN_new(),*up_bound = BN_new(),*a = BN_new(),*b= BN_new();
	BIGNUM *down_merge = NULL,*up_merge = NULL;
	Interval *interval_new;

	interval->Interval_get_bound(down_bound,up_bound);
	if(down_bound == NULL ||  up_bound == NULL)
		throw runtime_error("NULL bound");

	if(set.size()==0){
		set.push_back(interval);
		return ret;
	}

	list<Interval*>::iterator iter;
	for(iter = set.begin();iter != set.end();++iter){
		(*iter)->Interval_get_bound(a,b);
		if(BN_cmp(down_bound,a)<0){
			if(iter == set.begin()){
				down_merge = BN_dup(down_bound);
				break;
			}else{
				(*(--iter))->Interval_get_bound(a,b);
				if(BN_cmp(down_bound,b)>0)
					down_merge = BN_dup(down_bound);
				else
					down_merge = BN_dup(a);
				break;
			}
		}
	}

	if(down_merge == NULL){
		if(BN_cmp(down_bound,b)<=0)
			down_merge  = BN_dup(a);
		else
			down_merge  = BN_dup(down_bound);
	}


	for(iter = set.begin();iter != set.end();++iter){
		(*iter)->Interval_get_bound(a,b);
		if(BN_cmp(up_bound,b)<0){
			if(BN_cmp(up_bound,a)<0)
				up_merge =BN_dup(up_bound);
			else up_merge = BN_dup(b);
			break;
		}
	}

	if(up_merge == NULL)
		up_merge = BN_dup(up_bound);

	if(down_merge == NULL || up_merge == NULL)
		throw runtime_error("The bound of merge not correct set!");

	//test code
	/*
	BIO* bio = BIO_new_fp(stdout,BIO_NOCLOSE|BIO_FP_TEXT);
	cout<<"The merge down bound:";
	BN_print(bio,down_merge);
	cout<<endl<<"The merge up bound:";
	BN_print(bio,up_merge);
	cout<<endl;
	BIO_free(bio);
	*/
	//erase all  the sets to be merged in the bound
	//and record the situation
	for(iter = set.begin();iter != set.end();){
		(*iter)->Interval_get_bound(a,b);
		if(BN_cmp(down_merge,a)<=0 && BN_cmp(b,up_merge)<=0)
			 iter = set.erase(iter);
		else iter++;
	}
	//but the last interval can't be deleted
	if(set.size() == 1){
		iter = set.begin();
		(*iter)->Interval_get_bound(a,b);
		if(BN_cmp(down_merge,a)<=0 && BN_cmp(b,up_merge)<=0)
			 set.erase(iter);
	}


	//cout<<"The number of intervals after delete: "<<set.size()<<endl;
	//insert the interval to the situation
	interval_new = new Interval(down_merge,up_merge);
	list<Interval*>::iterator tmp;
	if(set.empty()){
		set.push_front(interval_new);
	}else
		for(iter = set.begin();iter  !=  set.end();++iter){
			(*iter)->Interval_get_bound(a,b);
			if(BN_cmp(up_merge,a)<0 && iter == set.begin()){
				set.push_front(interval_new);
			}else if(BN_cmp(b,down_merge)<0){
				tmp  = iter;
				tmp ++;
				if(tmp == set.end()){
					set.push_back(interval_new);
					break;
				}
				else{
					(*tmp)->Interval_get_bound(a,b);
					if(BN_cmp(a,up_merge)>0){
						set.insert(tmp,interval_new);
						break;
					}
				}
			}
		}
	return ret;
}

void IntervalSet::IntervalSet_Show(){
	BIO* bio = BIO_new_fp(stdout,BIO_NOCLOSE|BIO_FP_TEXT);
	list<Interval*>::iterator iter;
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	cout<<"The number of sets in the interval set: "<<set.size()<<endl;
	for(iter = set.begin();iter != set.end();++iter){
		(*iter)->Interval_get_bound(a,b);
		cout<<"Down bound of the interval: ";
		BN_print(bio,a);
		cout<<endl<<"Up bound of the interval: ";
		BN_print(bio,b);
		cout<<endl;
	}
	BN_free(a);
	BN_free(b);
}

BIGNUM* IntervalSet::IntervalSet_Totallen(){
	BIGNUM *ret;
	BIGNUM *total = BN_new();
	ListIter iter;

	BN_set_word(total,0);
	for(iter = set.begin();iter != set.end();++iter){
		ret = (*iter)->Interval_Size();
		BN_add(total,ret,total);
		BN_free(ret);
	}
	return total;
}
void IntervalSet::IntervalSet_Show_Totallen(){
	BIO* test_bio = BIO_new_fp(stdout,BIO_NOCLOSE|BIO_FP_TEXT);
	BIGNUM *total = IntervalSet_Totallen();
	cout<<"The total length of the Interval set: ";
	BN_print(test_bio,total);
	cout<<endl;
	BN_free(total);
	BIO_free(test_bio);
}

