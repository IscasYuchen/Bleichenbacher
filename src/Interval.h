//============================================================================
// Name        :Interval.h
// Author      : YuchenWang
// Version     : 0.0.2
// Description : The interval class header file
//============================================================================

#ifndef INTERVAL_H_
#define INTERVAL_H_

#include "def.h"

class Interval {
private:
	BIGNUM *down_bound;
	BIGNUM *up_bound;
public:
	Interval();
	//according to B, generate interval to [2B,3B-1]
	Interval(BIGNUM *B);
	Interval(BIGNUM *a,BIGNUM *b);
	~Interval();
	//if success, return 1 else return 0
	int Interval_set_bound(BIGNUM *a,BIGNUM *b);
	//updates the  interval as max(a,down_bound),min(b,up_bound)
	int Interval_update_bound(BIGNUM *a,BIGNUM *b);
	void  Interval_get_bound(BIGNUM *a,BIGNUM *b);
	//return the size of the interval
	BIGNUM* Interval_Size();
	Interval &  operator=(const Interval & interval);
};

#endif /* INTERVAL_H_ */
