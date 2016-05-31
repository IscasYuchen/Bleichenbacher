//============================================================================
// Name        : Oracle.cpp
// Author      : YuchenWang
// Version     : 0.0.2
// Description : The bleichenbacher oracle source file
//============================================================================
#include "Oracle.h"

Oracle::Oracle() {
	// TODO Auto-generated constructor stub
	priv_key = NULL;
	engine = NULL;
}

Oracle::Oracle(char *path,oracle_engine engine){
	//Read the private key
	BIO *file = BIO_new(BIO_s_file());
	if(BIO_read_filename(file,path)<0){
		ERR_print_errors_fp(stderr);
		throw runtime_error("Can't open public key file.");
	}else
		priv_key = PEM_read_bio_RSAPrivateKey(file,NULL,NULL,NULL);
	BIO_free(file);
	//Set the engine
	this->engine = engine;
}

int Oracle_start_listen(Oracle &oracle,int port,char *type){
	cout<<"enter a new query"<<endl;
	struct sockaddr_in o_ad,a_ad;
	int listen_fd = 0,query_fd = 0,a_len = 0,ret =0,p_len = 0,on =1;
	char buff[max_len];
	unsigned char *p = NULL;
	BIGNUM *c = BN_new();

	listen_fd = socket (AF_INET, SOCK_STREAM, 0);
	memset (&o_ad, '\0', sizeof(o_ad));
	o_ad.sin_family = AF_INET;
	o_ad.sin_addr.s_addr = inet_addr ("127.0.0.1");
	o_ad.sin_port = htons(port);
	if(setsockopt( listen_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on) )<0)
		throw runtime_error("Set socket reuse failure");
	if(bind(listen_fd, (struct sockaddr*) &o_ad,sizeof (o_ad))<0)
		throw runtime_error("Bind failure");

	 if(listen (listen_fd, 5)<0)
		 throw runtime_error("Start listening to a TCP connection failed");
	  a_len = sizeof(a_ad);
	  if((query_fd = accept (listen_fd, (struct sockaddr*) &a_ad, (socklen_t *)&a_len))<0)
		 throw runtime_error("Error occurs while listening to TCP connection");
	  close(listen_fd);

	  //read message from the TCP connection
	 do{
		 ret = read(query_fd,(void*)buff,max_len);
		 p = (unsigned char*)buff;
		 n2s(p,p_len);
		 BN_bin2bn(p,p_len,c);
		if(oracle.engine(oracle.priv_key,c,type))
			break;
		if(write(query_fd,"negative",strlen("negative"))<0)
			throw runtime_error("Socket write failed");
	 }while(true);

	 if(write(query_fd,"positive",strlen("positive"))<0)
		 throw runtime_error("Socket write failed");
	 close(query_fd);
	  return ret;
}


Oracle::~Oracle() {
	// TODO Auto-generated destructor stub
}

bool Oracle_engine(RSA *priv_key,BIGNUM *c,char *type){
	BIGNUM *m = BN_new();
	BN_CTX *ctx = BN_CTX_new();
	unsigned char *m_str = NULL;
	int m_len = 0,i = 0;
	bool ret = false;

	BN_mod_exp(m,c,priv_key->d,priv_key->n,ctx);
	m_len = BN_num_bytes(m);
	if(m_len == (BN_num_bytes(priv_key->n)-1)){
		m_str = new unsigned char[m_len];
		BN_bn2bin(m,m_str);
		if(m_str[0]==0x02)
			ret = true;
		if(strcmp(type,"TTT")==0){}
		else if(strcmp(type,"TFT") == 0){
			for(i = 1;i<9;i++)
				if(m_str[i] == 0x00)
					ret = false;
		}
		else if(strcmp(type,"FTT") == 0){
			bool FTT_ret = false;
			for(i = 9;i<m_len;i++)
				if(m_str[i]  == 0x00)
					FTT_ret = true;
			ret = FTT_ret &&  ret;
		}
		else if(strcmp(type,"FFT") == 0){
			for(i = 1;i < 9;i++)
				if(m_str[i] == 0x00)
					ret = false;
			bool FFT_ret = false;
			for(i = 9;i < m_len;i++)
				if(m_str[i]==0x00)
					FFT_ret = true;
			ret = FFT_ret && ret;
		}
		else if(strcmp(type,"FFF") == 0){
			for(i = 1;i < 9;i++)
				if(m_str[i] == 0x00)
					ret = false;
			if(m_str[m_len-6] !=  0x00)
				ret = false;
		}
		else throw runtime_error("No chosen type of oracle engine");
		free(m_str);
	}

	BN_CTX_free(ctx);
	BN_free(m);
	return ret;
}

