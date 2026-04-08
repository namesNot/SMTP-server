#include "ClassClientsStorage.h"

#include <stdio.h> // убрать

unsigned int ClientsStorage::HashFunction(unsigned int socket)
{
	return socket - hash_number;
}

void ClientsStorage::Add(Client *client)
{
	if(hash_number == 0)
		hash_number = client->GetSocket();
	count_clients++;
	table[HashFunction(client->GetSocket())] = client;

	for(int i=0;i<size_table;i++){
		printf("%p ", table[i]);
	}
		printf("\n");
}


void ClientsStorage::Delete(Client &client){
	table[HashFunction(client.GetSocket())] = NULL;
	delete &(client);
	count_clients -=1;
	for(int i=0;i<size_table;i++){
		printf("%p ", table[i]);
	}
		printf("\n");
}

ClientsStorage::ClientsStorage()
{
	size_table = 10;
	hash_number = count_clients = 0;
	table = new Client*[size_table];
	for(unsigned int i=0; i < size_table; i++)
		table[i] = NULL; 
}


