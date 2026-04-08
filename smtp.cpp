#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>
#include <signal.h>

#include <cerrno>
#include <cstring>


#include "ClassClientsStorage.h"





///////имею static переменную в ClassClient если буду реализовывать многопоточку надо учитывать!




void ConnectionRequest(unsigned int sd_listen, ClientsStorage &clients)
{
	struct sockaddr accept_addr;
	socklen_t size_addr = sizeof(accept_addr);

	unsigned int socket = accept(sd_listen, &accept_addr, &size_addr);
	fcntl(socket, F_SETFL, O_NONBLOCK);

	Client *obj = new Client(socket);
	clients.Add(obj);
}

void PerformAction(Client &client, ClientsStorage &clients)
{
	int result;
	switch(client.GetCurrentAction()){
		case Welcome: 
			result = client.SendResponse();
			if(result == 1)
				client.NextStep(AwaitingGreeting);
			break;
		case AwaitingGreeting:
			if(client.DataHasBeenRead() == false){
				result = client.GetMessage();
				break;
			}
			result = client.SendResponse();
			if(result == 1)
				client.NextStep(Mail);
			
			break;
		case Mail: 
			if(client.DataHasBeenRead() == false){
				result = client.GetMessage();
				break;
			}
			result = client.SendResponse();
			if(result == 1)
				client.NextStep(RCPT);
			break;
		case RCPT:
			if(client.DataHasBeenRead() == false){
				result = client.GetMessage();
				break;
			}
			result = client.SendResponse();
			//client.Print();
			if(result == 1)
				client.NextStep(Data);
			
			break;
		case Data:
			if(client.DataHasBeenRead() == false){
				result = client.GetMessage();
				break;
			}
			
			result = client.SendResponse();
			if(result == 1){
				if(client.IfAdditionalRecipient())
					client.NextStep(Data);
				else
					client.NextStep(GetData);//следующий
			}
			
			break;
		case GetData:
			result = client.GetMessageForData();
			/*result = client.SendResponse();
			if(result == 1)
				client.NextStep(Data);
			*/
			break;
			
		case SendCommands: break;

	}
	
	if(client.DeleteClient()){
		clients.Delete(client);
	}
}


int main(int argc, char **argv)
{
	if(argc < 1){
		puts("Too few arguments\n");
		return 1;
	}

	int sd_listen = socket(AF_INET, SOCK_STREAM, 0);
	if(sd_listen == -1){
		puts(strerror(errno));
		return 1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(3000);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);


	int result = bind(sd_listen, (sockaddr*)&addr, sizeof(addr));
	if(result == -1){
		puts("Error bind()\n");
		return 1;
	}

	if(listen(sd_listen, 5) == -1){
		puts("Error listen()\n");
		return 1;
	}
	

	fd_set readfds, writefds;
	int n;

	ClientsStorage clients;

	//signal(SIGPIPE,SIG_IGN);

	while(1){	
		signal(SIGPIPE,SIG_IGN);

		FD_ZERO(&readfds);		
		FD_ZERO(&writefds);		
		FD_SET(sd_listen,&readfds);
		n = sd_listen;
		for(unsigned int i = 0; i<clients.GetCountClients(); i++){
			unsigned int current_socket = clients[i].GetSocket();
			if(clients[i].ThereIsDataToSend())
				FD_SET(current_socket, &writefds);
			else
				FD_SET(current_socket, &readfds);
			n = current_socket;
		}	
		n++;

		result = select(n, &readfds, &writefds, NULL, NULL);

		if(FD_ISSET(sd_listen, &readfds)){
			ConnectionRequest(sd_listen, clients);
		}	




		for(unsigned int i = 0; i<clients.GetCountClients(); i++){
			if(FD_ISSET(clients[i].GetSocket(), &readfds) )
				PerformAction(clients[i], clients);
			if(FD_ISSET(clients[i].GetSocket(), &writefds) )
				PerformAction(clients[i], clients);
				
		}
	
	}
	
	
	//close(socket);
	close(sd_listen);


	return 0;
}



//1. Сделать обработку ошибок отдельно если new возвращает 0
//2. Что на счет деструктора в CLientStorage который удаляет массив и сразу все объекты
//3. Отправлять команды после получения приветствия
