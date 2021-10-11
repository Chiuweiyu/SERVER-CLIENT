#include <iostream>
#include <string.h>
#include <string>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include<arpa/inet.h>
#include<vector>
#include<pthread.h>
// SSL
#include <openssl/rsa.h>
#include <openssl/crypto.h>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

using namespace std;
#define HOME "./encryption/client/"
/* Make these what you want for cert & key files */
#define CERTF  HOME "cert.pem"
#define KEYF  HOME  "key.pem"
#define CHK_NULL(x) if ((x)==NULL) exit (1)
#define CHK_ERR(err,s) if ((err)==-1) { perror(s); exit(1); }
#define CHK_SSL(err) if ((err)==-1) { ERR_print_errors_fp(stderr); exit(2); }


const int MAX_STRING_LENGTH = 200;
const int MAX_BACKLOG = 10;


void Register( SSL* ssl, int& amount);
void Login( SSL* ssl, string& myName, int& myPort, bool& isLogin, int& amount);
void List(SSL* ssl, int&);
void Exit( SSL* ssl, bool& isLogin);
void BecomeServer(const SSL* ssl, int& serversockfd, struct sockaddr_in& serverInfo, struct sockaddr_in& clientInfo, int& myPort, bool& isLogin);
void AcceptConnection(int& serversockfd, int& forClientSockfd, struct sockaddr_in& clientInfo, const string& myName);
void *connection_handler(void* new_info);

typedef struct sockfdAndIP
{
    bool* isLogin;
    int* myPort;
    int* amount;
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
vector<Client> translateList(string msg, int&);
pthread_t MAIN = pthread_self();
void PRINT(vector<Client>& Set, int me);
SSL_CTX *InitSSL_CTX(void)
{
    const SSL_METHOD *method = TLS_client_method(); /* Create new client-method instance */
    SSL_CTX *ctx = SSL_CTX_new(method);

    if (ctx == nullptr)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ctx;
};

SSL*     ssl;

int main(int argc , char *argv[])
{

    int sockfd = socket(AF_INET , SOCK_STREAM , 0);
    if (sockfd == -1)
        cout << "Fail to create a socket.";
    SSL_CTX* ctx;
    
    const SSL_METHOD *meth;
    OpenSSL_add_ssl_algorithms();
    meth = TLS_client_method();
    SSL_load_error_strings();
    ctx = SSL_CTX_new (meth);                        CHK_NULL(ctx);
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


    struct sockaddr_in info;
    bzero(&info,sizeof(info));
    info.sin_family = AF_INET;
    string addr = "";
    int serverport = 0;
    while (true)
    {
        cout << "Please input the address: ";
        cin >> addr;
        cout << "Please enter the port: ";
        cin >> serverport;

        info.sin_addr.s_addr = inet_addr(addr.c_str());
        info.sin_port = htons(serverport);
        int err = connect(sockfd, (struct sockaddr*)&info, sizeof(info));
        if(err==-1)
            cout << "Connection ERROR!! \n";
        else{
            
            ssl = SSL_new (ctx);                         CHK_NULL(ssl);    
            SSL_set_fd (ssl, sockfd);
            err = SSL_connect (ssl);                     CHK_SSL(err);
            char receiveMessage[MAX_STRING_LENGTH];
            memset(receiveMessage, '\0', sizeof(receiveMessage));
            SSL_read(ssl ,receiveMessage, MAX_STRING_LENGTH); //Receiver buffer 長度不夠!
            cout << "==========================" << endl
                 << endl;
            cout << receiveMessage 
                 << endl;
            cout << "==========================" << endl;
            break;
        }
    }
    
    //////////////////////////////////
    //conversation between clients
    
    bool isLogin = 0;
    string myName = "";
    char mode = '0';
    int myPort = 0;
    int amount = 0;
    int serversockfd, forClientSockfd;
    struct sockaddr_in clientInfo, serverInfo;
    cout << "HELLO" << endl;
    while (true)
    {
        if (sockfd == -1)
        {
            break;
        }
        if (!isLogin)
        {
            cout << "What do you want to do?" << endl;
            cout << "-> " << "1. Register" << endl
                 << "-> " << "2. Login" << endl;

    
            cout << "(Plaese input the number) : ";
            cin >> mode;
            cin.ignore(MAX_STRING_LENGTH, '\n');
            if (mode!= '1' and mode!= '2')
            {
                cout << "==========================\n" << endl;
                cout << "INVALID mode. Choose again! \n" << endl;
                cout << "==========================" << endl;
                continue;
            }
        }
        else
        {
            cout << "Hello! " << myName <<endl;
            cout << "What do you want to do?" << endl;
            cout << "-> " << "3. Account balance & list" <<endl
                 << "-> " << "4. Transfer " << endl
                 << "-> " << "5. Logout"<< endl
                 << "(Plaese input the number) : ";
            cin.ignore(MAX_STRING_LENGTH, '\n');
            cin >> mode;
            if (mode!= '3' and mode!= '4' and mode!= '5')
            {
                cout << "==========================\n" << endl;
                cout << "INVALID mode. Choose again! \n" << endl;
                cout << "==========================" << endl;
                continue;
            }
        }
        pthread_t sniffer_thread;

        if (mode == '1' && MAIN == pthread_self())
            Register(ssl, amount);
        else if (mode == '2' && MAIN == pthread_self())
        {
            Login(ssl, myName, myPort, isLogin, amount);
            serversockfd = 0;
            forClientSockfd = 0;
            
            sockfdAndIP* new_info = new sockfdAndIP;
            new_info->isLogin = &isLogin;
            new_info->myPort = &myPort;
            new_info->amount = &amount;
            
            if( pthread_create( &sniffer_thread , NULL ,  connection_handler , (void*) new_info) < 0)
            {
                cout << "could not create thread";
                return 1;
            }
        }
        else if (mode == '3' && MAIN == pthread_self())
            List(ssl, amount);
        else if (mode == '5' && MAIN == pthread_self())
        {
            Exit(ssl, isLogin);
            isLogin = 0;
       //     break;
        }
        else if (mode == '4' && MAIN == pthread_self())
        {
            cout << "============================" << endl;
            cout << "Hi! " << myName << ". Welcome to transfer system.\n"
                 << "You have $" << amount << ".\n"
                 << "Here is the list of online-account:\n";
            int me = 0;
            for(int i = 0; i < clientSet.size(); i++)
                if(clientSet[i].getName() == myName)
                    me = i;
            PRINT(clientSet, me);

            int payee;
            int payAmount;
            string payeeName;
            cout << "Who do you want to transfer?" << endl
                 << "ID: ";  cin >> payee;
            
            cout << "How much do you want to transfer?" << endl
                 << "Payment: "; cin >> payAmount;
        
        
            if(payee < clientSet.size() && payee >= 0 && amount >= payAmount && payee != me) 
            {
                int sockfd2 = socket(AF_INET , SOCK_STREAM , 0);
                SSL_CTX* ctx2;
                SSL*     ssl2;
                const SSL_METHOD *meth2;
                OpenSSL_add_ssl_algorithms();
                
                meth2 = TLS_client_method();
                SSL_load_error_strings();
                ctx2 = SSL_CTX_new (meth2);          CHK_NULL(ctx2);
                
                if (!ctx2) {
                    ERR_print_errors_fp(stderr);
                    exit(2);
                }
                if (SSL_CTX_use_certificate_file(ctx2, CERTF, SSL_FILETYPE_PEM) <= 0) {
                    ERR_print_errors_fp(stderr);
                    exit(3);
                }
                if (SSL_CTX_use_PrivateKey_file(ctx2, KEYF, SSL_FILETYPE_PEM) <= 0) {
                    ERR_print_errors_fp(stderr);
                    exit(4);
                }

                if (!SSL_CTX_check_private_key(ctx2)) {
                    fprintf(stderr,"Private key does not match the certificate public key\n");
                    exit(5);
                }
                struct sockaddr_in info2;
                bzero(&info,sizeof(info2));
                info2.sin_family = AF_INET;
                string addr2 = "";
                int othersPort = 0;

                addr2 = clientSet[payee].getIP();
                othersPort = clientSet[payee].getPort();
                payeeName = clientSet[payee].getName();
                amount -= payAmount;

                info2.sin_addr.s_addr = inet_addr(addr2.c_str());
                info2.sin_port = htons(othersPort);
                int err3 = connect(sockfd2, (struct sockaddr*)&info2, sizeof(info2));

                ssl2 = SSL_new (ctx2);                         CHK_NULL(ssl);    
                SSL_set_fd (ssl2, sockfd2);
                int err = SSL_connect (ssl2);                     CHK_SSL(err);
                if(err3==-1)
                {
                    cout << "Connection ERROR!! \n";
                    cout << "==========================" << endl; 
                    continue;
                }
                string msg2;
                msg2 = myName + string("#") + to_string(payAmount) + string("#") + payeeName + string("\r\n");
                SSL_write(ssl2, msg2.c_str(), strlen(msg2.c_str()));
                
            }
            else
            {
                cout << "Name INVALID or money not enough..." << endl;
                     
            }
            
                
            cout << "============================\n";
        }
    }
    
    return 0;
}




void Register( SSL* ssl, int& amount)
{
    string msg = "";
    cout << "Input your account name: ";
    string name;
    cin >> name;
    cout << "Input your initial balance (0~2147483647): ";
    double temp ;
    while(cin >> temp)
        if (temp >= 0 and temp - 2147483647 <= 0)
            break;
        else
            cout << "Input range = [0, 2147483647]. Try Again:";
    
    amount = static_cast<int>(temp);
    msg = "REGISTER#" + name + string("#") + to_string(amount) + string("\r\n");
    SSL_write(ssl, msg.c_str(), strlen(msg.c_str()));
    char receiveMessage[MAX_STRING_LENGTH];
    memset(receiveMessage, '\0', sizeof(receiveMessage));

    SSL_read(ssl,receiveMessage, MAX_STRING_LENGTH);
    cout << "==========================" << endl
            << endl;
    cout << receiveMessage 
            << endl;
    cout << "==========================" << endl;
    
} 

void Login(SSL* ssl, string& myName, int& myPort, bool& isLogin, int& amount)
{
    string msg = "";
    cout << "Input your account name: ";
    cin >> myName;
    cout << "Input the port what you want to use (1024~65536): ";
    while(cin >> myPort)
        if (myPort >= 1024 and myPort <= 65536)
            break;
        else
            cout << "Input range = [1024, 65536]. Try Again:";

    msg = myName + string("#") + to_string(myPort) + string("\r\n");
    
    SSL_write(ssl, msg.c_str(), strlen(msg.c_str()));
    char receiveMessage[MAX_STRING_LENGTH];
    memset(receiveMessage, '\0', sizeof(receiveMessage));

    SSL_read(ssl,receiveMessage, MAX_STRING_LENGTH);
    cout << "==========================\n"
            << "\n";
    cout << receiveMessage 
            << "\n";
    cout << "==========================" << endl;
    string rcM = string(receiveMessage);
    size_t cnHasLogged = rcM.find("This connection has logged");
    size_t auth_fail = rcM.find("220 AUTH_FAIL");
    size_t acHasLogged = rcM.find("This account has been logged");
    size_t portError = rcM.find("Port number must be in range 1024~65536");
    if (cnHasLogged == string::npos and 
        auth_fail == string::npos and
        acHasLogged == string::npos and
        portError == string::npos){
        isLogin = true; 
        clientSet = translateList(string(receiveMessage), amount);
    } 
        
}

void List( SSL* ssl, int& amount)
{
    string msg = "";
    msg = "List";
    SSL_write(ssl, msg.c_str(), strlen(msg.c_str()));
    char receiveMessage[MAX_STRING_LENGTH];
    memset(receiveMessage, '\0', sizeof(receiveMessage));

    SSL_read(ssl,receiveMessage, MAX_STRING_LENGTH);
    cout << "==========================" << endl
            << endl;
    cout << receiveMessage 
            << endl;
    cout << "==========================" << endl;
    clientSet = translateList(string(receiveMessage), amount);
}


void Exit(SSL* ssl, bool& isLogin)
{
    string msg = "";
    msg = "Exit";
    SSL_write(ssl, msg.c_str(), strlen(msg.c_str()));
    char receiveMessage[MAX_STRING_LENGTH];
    memset(receiveMessage, '\0', sizeof(receiveMessage));
    SSL_read(ssl,receiveMessage, MAX_STRING_LENGTH);
    cout << "==========================" << endl
            << endl;
    cout << receiveMessage 
            << endl;
    cout << "==========================" << endl;
    isLogin = 0;
}



vector<Client> translateList(string msg, int& amount)
{
    vector<Client> result;
    size_t pos = msg.find("\r\n");
    size_t split;
    amount = stoi(msg.substr(0, pos));
    msg = msg.substr(pos + 2, string::npos);
    pos = msg.find("\r\n");
    int onlineCnt = stoi(msg.substr(0, pos));
    msg = msg.substr(pos + 2, string::npos);
    for(int i = 0; i < onlineCnt; i++)
    {
        split = msg.find("#");
        string name = msg.substr(0, split);
        msg = msg.substr(split + 1, string::npos);
        split = msg.find("#");
        string IP = msg.substr(0, split);
        msg = msg.substr(split + 1, string::npos);
        split = msg.find("\r\n");
        int port = stoi(msg.substr(0, split));
        msg = msg.substr(split + 2, string::npos);
        Client temp = Client(name, 0, IP);
        temp.setPort(port);
        result.push_back(temp);
    }

    return result;

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
	if(login)
	{
		this->login = false; 
		this->port = 0;
	}
	else
		cout << "This Account has not logged-in." <<endl;
}


void *connection_handler(void* new_info)
{
	//Get the socket descriptor

	sockfdAndIP info = *(sockfdAndIP*)new_info;
    int * myPort = info.myPort;
    bool * isLogin = info.isLogin;
    int* amount = info.amount;

    SSL_CTX* ctxServer;
    SSL*     sslServer;
    const SSL_METHOD *methServer = TLS_method();
    ctxServer = SSL_CTX_new (methServer);
    if (SSL_CTX_use_certificate_file(ctxServer, CERTF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(3);
	}
	if (SSL_CTX_use_PrivateKey_file(ctxServer, KEYF, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		exit(4);
	}

	if (!SSL_CTX_check_private_key(ctxServer)) {
		fprintf(stderr,"Private key does not match the certificate public key\n");
		exit(5);
    }

    int serversockfd = 0, forClientSockfd = 0;
    struct sockaddr_in clientInfo, serverInfo;
	serversockfd = socket(AF_INET , SOCK_STREAM , 0);

	bzero(&serverInfo,sizeof(serverInfo));
    bzero(&clientInfo,sizeof(clientInfo));

    serverInfo.sin_family = AF_INET;
    serverInfo.sin_addr.s_addr = INADDR_ANY;
    serverInfo.sin_port = htons(*myPort);

    int err = bind(serversockfd, (struct sockaddr *)&serverInfo, sizeof(serverInfo));
    if (err == -1)
    {
        cout << "Binding ERROR!! \n";
        *isLogin = false;
        return 0;
    }
        
    listen(serversockfd, MAX_BACKLOG);
    char messageFromClient[MAX_STRING_LENGTH];
    socklen_t addrlen = sizeof(clientInfo);
    while (pthread_self() != MAIN)
    {
        if (forClientSockfd == 0)
            forClientSockfd = accept(serversockfd,(struct sockaddr*) &clientInfo, &addrlen);
        sslServer = SSL_new (ctxServer);                      
        SSL_set_fd(sslServer ,forClientSockfd);
        err = SSL_accept (sslServer);                    CHK_SSL(err);

        memset(messageFromClient, '\0', sizeof(messageFromClient));
        int recvd = SSL_read (sslServer, messageFromClient, MAX_STRING_LENGTH);
        string receiveMessage = string(messageFromClient);
        string receiveMessageBackup = receiveMessage.substr(0, string::npos);
        size_t ind_split = receiveMessage.find("#");
       
        string senderName = receiveMessage.substr(0, ind_split);
        receiveMessage = receiveMessage.substr(ind_split + 1, string::npos);
        ind_split = receiveMessage.find("#");
        int payAmount = stoi(receiveMessage.substr(0, ind_split));
        if(*amount < 2147483647 - payAmount)
            *amount += payAmount;
        else
            *amount = 2147483647;
        
        receiveMessage = receiveMessage.substr(ind_split + 1, string::npos);
        ind_split = receiveMessage.find("\r\n");
        string myName = receiveMessage.substr(0, ind_split);

        if(recvd)
        {
            SSL_write(ssl, receiveMessageBackup.c_str(), strlen(receiveMessageBackup.c_str()));
            memset(messageFromClient, '\0', sizeof(messageFromClient));
            SSL_read(ssl, messageFromClient, MAX_STRING_LENGTH );
            forClientSockfd = 0;
        }
    }
    
    
    bzero(&clientInfo,sizeof(clientInfo));
    delete (sockfdAndIP*)new_info;
    return 0;
    
}

void PRINT(vector<Client>& Set, int me)
{
    cout << "====================";
    for(int i = 0; i < Set.size(); i++)
    {
        if (i != me)
            cout <<endl << i << ". " << Set[i].getName();
    }
    cout << "\n====================\n";
}
