//============================================================================
// Name        : IntervalSet.h
// Author      : YuchenWang
// Version     : 0.0.1
// Description : The Bleichenbacher IntervalSet header file
//============================================================================


#ifndef INTERVALSET_H_
#define INTERVALSET_H_

#include "Interval.h"

typedef list<Interval*>::iterator ListIter;

class IntervalSet {
private:
	list<Interval*> set;
public:
	IntervalSet();
	IntervalSet(BIGNUM *B);
	virtual ~IntervalSet();
	int IntervalSet_Num();
	//Union the interval with the intervals has stored in the set
	int IntervalSet_Union(Interval *interval);
	//The total length of the intervalset
	BIGNUM* IntervalSet_Totallen();
	//Show all the elements in the intervalset
	void IntervalSet_Show();
	//Show the total length of the intervalset
	void IntervalSet_Show_Totallen();
	friend class Adversary;
};

#endif /* INTERVALSET_H_ */
