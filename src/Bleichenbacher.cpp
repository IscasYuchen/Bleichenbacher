//============================================================================
// Name        : Bleichenbacher.cpp
// Author      : YuchenWang
// Version     : 0.0.2
// Description : Bleichenbacher attack and oracle program
//============================================================================
#include "def.h"
#include "Oracle.h"
#include "Adversary.h"
#include "Interval.h"
#include "IntervalSet.h"

using std::strcmp;

const int default_port = 5555;
char default_plain_text[] = "aaa";
char default_oracle_type[] = "TTT";

//void test_intervalset();

int main(int argc,char *argv[]) {
	int is_oracle = 0,is_adversary = 0,badops = 0,port = 0;
	Adversary *adversary = NULL;
	Oracle *oracle = NULL;
	char *prikey_file = NULL,*pubkey_file = NULL,*plain_text = NULL,*port_text = NULL,*oracle_type = NULL;

	argc--;
	argv++;
	while(argc>0){
		if(strcmp(*argv,"-oracle") == 0)
			is_oracle = 1;
		else if (strcmp(*argv,"-adversary") == 0)
			is_adversary = 1;
		else if(strcmp(*argv,"-pubkey") == 0){
			if(--argc == 0){
				cout<<"you need to provide a rsa public pem file after -pubkey"<<endl;
				badops = 1;
			}
			pubkey_file =  *(++argv);
		}else if(strcmp(*argv,"-plaintext") == 0){
			if(--argc == 0){
				cout<<"You need to provide a plaintext after -plaintext"<<endl;
				badops = 1;
			}
			plain_text =  *(++argv);
		}else if(strcmp(*argv,"-prikey") == 0){
			if(--argc == 0){
				cout<<"You need to provide a rsa private pem file after -prikey"<<endl;
				badops =1;
			}
			prikey_file =  *(++argv);
		}else if(strcmp(*argv,"-type") == 0){
			if(--argc == 0){
				cout<<"You need to provide the type of the oracle after -type"<<endl;
				badops =1;
			}
			oracle_type =  *(++argv);
		}else if(strcmp(*argv,"-port") == 0){
			if(--argc == 0){
				cout<<"You need to provide a port number  before -port"<<endl;
				badops =1;
			}
			port_text = *(++argv);
			port = atoi(port_text);
		}else
			badops =1;
		argc--;
		argv++;
	}

	if(badops){
		cout<<"The program shows how bleichenbacher attack works:"<<endl;
		cout<<"-oracle				This program will run as oracle."<<endl;
		cout<<"-adversary			This  program will run as adversary."<<endl;
		cout<<"-port				In which port the program runs.(default:5555)"<<endl;
		cout<<"-prikey file			The private key that the oracle uses."<<endl;
		cout<<"-pubkey file			The public key that the adversary uses."<<endl;
		cout<<"-plaintext string		The plaintext that the adversary want to decrypt without private key.(default:aaa)"<<endl;
		cout<<"-type string	 		The type of the oracle,including TTT.(default: TTT)"<<endl;
		goto end;
	}
	try{
		if(port == 0)
			port =	default_port;
		if(oracle_type == NULL)
			oracle_type = default_oracle_type;
		if(plain_text == NULL)
			plain_text = default_plain_text;
		if(prikey_file == NULL && pubkey_file == NULL)
			throw runtime_error("You must set a key file in a program launch");
		if(is_oracle == 1  && prikey_file != NULL){
				oracle = new Oracle(prikey_file,Oracle_engine);
			while(true)
				Oracle_start_listen(*oracle,port,oracle_type);
		}else if(is_adversary == 1 && pubkey_file != NULL){
			adversary = new  Adversary(pubkey_file,plain_text,strlen(plain_text));
		    adversary->Adversary_Attack(port);
		}else{
			throw(" you have to set  a role");
		}
	}catch(runtime_error &s){
		cout<<"Error reason: "<<s.what()<<endl;
	}catch(...){
		cout<<"Unkonwn error"<<endl;
	}
end:
	return 0;
}


