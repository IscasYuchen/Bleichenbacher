#include "Adversary.h"
#include "Oracle.h"
#include "IntervalSet.h"
#include "Interval.h"

void test_intervalset(){
	//the  code is for test IntervalSet
		BIGNUM *a = BN_new();
		BIGNUM *b = BN_new();
		BN_set_word(a,10);
		BN_set_word(b,20);
		IntervalSet intervalset;
		Interval interval(a,b);
		intervalset.IntervalSet_Union(&interval);
		intervalset.IntervalSet_Show();
		BN_set_word(a,25);
		BN_set_word(b,30);
		Interval insert(a,b);
		intervalset.IntervalSet_Union(&insert);
		intervalset.IntervalSet_Show();
		BN_set_word(a,22);
		BN_set_word(b,44);
		Interval insert_2(a,b);
		intervalset.IntervalSet_Union(&insert_2);
		intervalset.IntervalSet_Show();
		BN_set_word(a,40);
		BN_set_word(b,50);
		Interval insert_3(a,b);
		intervalset.IntervalSet_Union(&insert_3);
		intervalset.IntervalSet_Show();

		BIO* test_bio = BIO_new_fp(stdout,BIO_NOCLOSE|BIO_FP_TEXT);
		BIGNUM *total = intervalset.IntervalSet_Totallen();
		cout<<"The total length of the Interval set: ";
		BN_print(test_bio,total);
		cout<<endl;
		BIO_free(test_bio);
}
