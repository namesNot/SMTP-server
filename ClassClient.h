#include "EnumStep.h"
#include "EnumError.h"
#include "ClassMailTransaction.h"
#include <unistd.h>
#include <cstring>
#include <cstdio>

class Client{
	unsigned int socket;
	int size_buffer;
	char *buffer;
	Step current_step, last_step;
	MailTransaction transaction;
	const char *error;
	const char *response;
	bool there_is_data_to_send;
	bool delete_client;
	bool all_data_is_read;

public:
	Client(unsigned int sct);
	~Client();
	unsigned int GetSocket() const {return socket;}
	int SendResponse();
	bool GetMessage();
	bool GetMessageForData();
	int SendError();
	bool HaveError();
	Step GetCurrentAction(){ return current_step; }
	bool ThereIsDataToSend(){return there_is_data_to_send;}
	void NextStep(Step next_step = Welcome);
	void Destroy(){ delete_client = 1;}
	bool DeleteClient(){return delete_client;}
	bool DataHasBeenRead(){ return all_data_is_read;}
	bool IfAdditionalRecipient(){return transaction.CheckAdditionalRecipients();}

	void Print(){printf("%s %s\n", transaction.PrintSender(), transaction.PrintRCPT());}
private:
	//const char *IdentifyError(Error &error);
	bool AnalisysAnswer();
	bool AnalyzeWelcome();
	bool AnalisysMail();
	bool AnalisysRCPT();
	bool AnalisysData();
	bool AnalisysGetData();
	bool AnalyzeHELO(int &start_command, int &start_domain);
	bool AnalyzeDomain(int &start_domain, int &domain_part_lenght, char end_str);
	void SetUnSuccessfulResponse(const char *str_error){error = str_error; there_is_data_to_send = 1; }
	void SetSuccessfulResponse(const char *str){ response = str; there_is_data_to_send = 1;};
	void ConvertToUppercase();

	bool AnalyzeMailFrom(int &argument_start_position);
	bool AnalyzeMailFromArgument(int local_part_start_position);
	bool AnalyzeDomainPart(int &start_position, int &domain_part_lenght);
	bool ValidDomainChars(int pos);
	bool AnalyzeLocalPart(int start_position, int &domain_part_start_position, int &local_part_lenght);
	bool ValidLocalChars(int pos);

	
	bool AnalyzeRcptToArgument(int local_part_start_position);
	bool AnalyzeRcptTo(int &argument_start_postition);

	int MyStrchr(char *buffer, char chr); // пока она здесь, потом перенесу
					      //
	
	int AnalyzeMessageForData(int read_count);
	bool GetMessageForData(char *buffer);
};

