#include <iostream>
#include<string.h>	//strlen
#include<string>
#include<stdlib.h>	//strlen
#include<sys/socket.h>
#include<arpa/inet.h>	//inet_addr
#include<unistd.h>	//write
#include<pthread.h> //for threading , link with lpthread
#include<vector>
// SSL
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;
const int MAX_STRING_LENGTH = 200;
const int MAX_BACKLOG = 10;

#define HOME "./encryption/server/"
/* Make these what you want for cert & key files */
#define CERTF  HOME "cert.pem" 
#define KEYF  HOME "key.pem"
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }

void *connection_handler(void *);
string generateList(const string& userName);

typedef struct sockfdAndIP
{
	SSL* ssl;
	string IP;
}sockfdAndIP;

class Client
{
private:
	string name;
	int amount;
	bool login;
	int port;
	string IP;
public:
	Client(string name, int amount, string IP);
	void Login(int port);
	void Logout();
	string getName() {return this->name;};
	int getAmount() {return this->amount;};
	int getPort() {return this->port;};
	void setPort(int port) {this->port = port;};
	void deltaAmount(int amount) {this->amount += amount;};
	string getIP() {return this->IP;};
	bool Online() {return this->login;};
};

vector<Client> clientSet;






int main(int argc , char *argv[])
{
	int sockfd , new_socket , *new_sock;
	struct sockaddr_in server , client;
	char message[MAX_STRING_LENGTH];
	SSL_CTX* ctx;
	SSL*     ssl;
	X509*    client_cert;
	const SSL_METHOD *meth;
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
	meth = TLS_server_method();
	ctx = SSL_CTX_new (meth);
	if (!ctx) {
		ERR_print_errors_fp(stderr);
		exit(2);
	}
	if (SSL_CTX_use_certificate_file(ctx, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctx, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}

	if (!SSL_CTX_check_private_key(ctx)) {
		fprintf(stderr,"Private key does not match the certificate public key\n");
		exit(5);
    }


	
	//Create socket
	sockfd = socket(AF_INET , SOCK_STREAM , 0);
	if (sockfd == -1)
		cout << "Could not create socket" << endl;


	
	int portNum = 0 ;
	cout << "Please input a port number:" << endl;
	cin >> portNum;
	//Prepare the sockaddr_in structure
	server.sin_family = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port = htons( portNum );
	
	//Bind
	if( bind(sockfd,(struct sockaddr *)&server , sizeof(server)) < 0)
	{
		cout << "Binding ERROR" << endl;
		return 1;
	}
	cout << "Binding port #" << portNum << " successfully!\n";
	
	listen(sockfd , MAX_BACKLOG);
	
	//Accept and incoming connection
	cout << "Waiting for connections..." <<endl;

	socklen_t addrlen = sizeof(struct sockaddr_in);

	while( (new_socket = accept(sockfd, (struct sockaddr *)&client, &addrlen ) ) )
	{
		string connectAC = "Connection accepted!";
		cout << connectAC <<endl;
	//	send(sockfd, connectAC.c_str(), strlen(connectAC.c_str()), 0);
		//Reply to the client
		ssl = SSL_new (ctx);                         CHK_NULL(ssl);    
		SSL_set_fd (ssl,new_socket);
		int err = SSL_accept (ssl);                        CHK_SSL(err);
		
		pthread_t sniffer_thread;
		
		sockfdAndIP* new_info = new sockfdAndIP;
		new_info->ssl = ssl;
		new_info->IP = string( inet_ntoa( client.sin_addr ));
		
		if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) new_info) < 0)
		{
			cout << "could not create thread";
			return 1;
		}

		
		//Now join the thread , so that we dont terminate before the thread
		//pthread_join( sniffer_thread , NULL);
		cout << "Handler assigned!\n";
	}
	
	if (new_socket<0)
	{
		perror("accept failed");
		return 1;
	}
	
	return 0;
}

/*
 * This will handle connection for each client
 * */
void *connection_handler(void* new_info)
{
	//Get the socket descriptor
	

	sockfdAndIP info = *(sockfdAndIP*)new_info;
	SSL* ssl = info.ssl;
	string IP = info.IP;
	Client* currentUser = nullptr;
	string message;
	
	
//	server_cert = SSL_get_peer_certificate (ssl);       CHK_NULL(server_cert);

	//Send some messages to the client
	message = "Connection accepted!\n";
	SSL_write(ssl , message.c_str(), strlen(message.c_str()));
	char messageFromClient[MAX_STRING_LENGTH];
	
	while(true)
	{
		memset(messageFromClient, '\0', sizeof(messageFromClient));
        if( SSL_read(ssl, messageFromClient, MAX_STRING_LENGTH) > 0 ) 
        {
            string RCM = string(messageFromClient);
			cout << "Recieved: " << RCM << endl;
			if(RCM.find("REGISTER") != string::npos)
			{
				string name = RCM.substr (9, string::npos);
				size_t ind_split = name.find("#");
				float amount = stof(name.substr(ind_split+1, string::npos));
				name = name.substr(0, ind_split);
				bool OK = true;
				
				if (amount > 2147483647 or amount < 0)  //out of range
				{
					OK = false;
					message = "210 FAIL\nAmount needed <= 2147483647 \r\n";
					SSL_write(ssl , message.c_str(), strlen(message.c_str()));
				}
				else
				{
					for(int i = 0; i < clientSet.size(); i++)
						if (name.compare(clientSet[i].getName()) == 0) //name exists! 
						{
							OK = false;
							message = "210 FAIL\r\n";
							SSL_write(ssl , message.c_str(), strlen(message.c_str()));
							break;	
						}
				}
				
				if(OK)
				{
					clientSet.push_back(Client(name, static_cast<int>(amount), IP));
					message = "100 OK\r\n";
					SSL_write(ssl , message.c_str(), strlen(message.c_str()));
					cout << generateList(name);
				}
			}
			else if(RCM.find("List") != string::npos)
			{
				if(currentUser->Online())
					message = generateList(currentUser->getName());
				SSL_write(ssl , message.c_str(), strlen(message.c_str()));
			}
			else if(RCM.find("Exit") != string::npos)
			{
				if(currentUser->Online())
					message = "Bye\r\n";
				SSL_write(ssl , message.c_str(), strlen(message.c_str()));
				currentUser ->Logout();
				currentUser = nullptr;
			}
			else //LOGIN OR TRANSFER
			{
				size_t ind_split = RCM.find("#");
				string name = RCM.substr(0, ind_split);
				string othersName;
				RCM = RCM.substr(ind_split+1, string::npos);
				size_t ind_end =  RCM.find("#");
				
				
				if (ind_end != string::npos) //TRANSFER
				{
					int Num = stoi(RCM.substr(0, ind_end));
					RCM = RCM.substr(ind_end+1, string::npos);
					ind_end = RCM.find("\r\n");
					othersName = RCM.substr(0, ind_end);
					for (int i = 0; i < clientSet.size(); i++)
					{
						if (clientSet[i].getName() == name) //payer
							clientSet[i].deltaAmount(-Num);
						else if (clientSet[i].getName() == othersName)
							clientSet[i].deltaAmount(Num);
					}
					message = "Transfer DONE.\n";
					SSL_write(ssl , message.c_str(), strlen(message.c_str()));

				}
				else
				{
					
					int port = stoi(RCM);
					if(port < 1024 or port > 65536)
					{
						message = "Port number must be in range 1024~65536!\r\n";
						SSL_write(ssl , message.c_str(), strlen(message.c_str()));
						continue;
					}
					else if(currentUser != nullptr) //A User login in this connection.
					{
						message = "This connection has logged\r\n";
						SSL_write(ssl , message.c_str(), strlen(message.c_str()));
						continue;
					}
					else
					{
						for (int i = 0; i < clientSet.size(); i++)
						{
							if(name.compare(clientSet[i].getName()) == 0)
							{
								currentUser = &(clientSet[i]);
								break;
							}
						}
					}

					if (currentUser == nullptr ) //NOT FOUND USER
					{
						message = "220 AUTH_FAIL\r\n";
						SSL_write(ssl , message.c_str(), strlen(message.c_str()));
					}
					else
					{
						if (!currentUser ->Online()) 
						{
							currentUser->Login(port);
							message = generateList(currentUser->getName());
							SSL_write(ssl , message.c_str(), strlen(message.c_str()));
						}
						else //THIS USER IS ONLINE
						{
							message = "This account has been logged\n";
							SSL_write(ssl , message.c_str(), strlen(message.c_str()));
						}
					}
				}
			}	
        }
	}
	
	delete (sockfdAndIP*)new_info;
	return 0;
}


Client::Client(string name, int amount, string IP)
{
	this->name = name;
	this->amount = amount;
	this->IP = IP;
	this->login = false; 
	this->port = 0;
}

void Client::Login(int port)
{
	this->login = true; 
	this->port = port;
}

void Client::Logout()
{
	if(this->login)
	{
		this->login = false; 
		this->port = 0;
	}
	else
		cout << "This Account has not logged-in." <<endl;
}

string generateList(const string& userName)
{
	int onlineUserCnt = 0;
	int myAmount = 0;
	string msg = "";
	for(int i = 0; i < clientSet.size(); i++)
	{
		if(clientSet[i].Online()) 
		{
			onlineUserCnt ++;
			msg += ( clientSet[i].getName() + string("#") + 
			         clientSet[i].getIP() + string("#") + 
					 to_string(clientSet[i].getPort()) + string("\r\n") );
			
			if(userName.compare( clientSet[i].getName() ) == 0)
				myAmount = clientSet[i].getAmount();
		}
	}
	msg = to_string(myAmount) + string("\r\n") + 
	      to_string(onlineUserCnt) + string("\r\n") + 
		  msg;

	return msg;
}