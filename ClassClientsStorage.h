
#include "ClassClient.h"

class ClientsStorage{
	Client **table;
	unsigned int size_table;
	unsigned int count_clients;
	unsigned int hash_number;


public:
	ClientsStorage();
	~ClientsStorage(){ delete [] table; }
	
	void Add(Client *obj);
	void Delete(Client &client);
	unsigned int GetCountClients() { return count_clients;}

	 Client& operator[](unsigned int i) { return *(table[i]); }
		
private:
	unsigned int HashFunction(unsigned int socket);

};

