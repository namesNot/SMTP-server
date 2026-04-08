#include <unistd.h>
#include <cstring>
#include <stdio.h>
#include "ClassMailTransaction.h"

MailTransaction::MailTransaction()
{
	address_sender = NULL;
	size_arr_address = 3;
	count_addr_recipients = 0;
	arr_address = new char*[size_arr_address];
	add_additional_recipients = 0;
	size_data = 1000;
	current_size_data = 0;
	
	data = new char[size_data];
	dot_received = CR_received = CRLF_received = false;
	header_block_end_index = -1;
	buffer_incomplete_CRLF = new char[3];
	buffer_incomplete_CRLF[0] = '\0';


	mail_data_max_size = 100;
       	mail_data_size = 0;
	mail_data = new char[mail_data_max_size];

}

void MailTransaction::AddAddressSender(char* buffer, int len)
{	
	//оставляем обратный адрес пустым
	if(len == 0)
		return;
	address_sender = new char[len+1];
	buffer[len] = '\0';
	strcpy(address_sender, buffer);
}
bool MailTransaction::AddAddressRecipients(char *buffer, int len)
{
	if(count_addr_recipients == size_arr_address)
		return 0;
	arr_address[count_addr_recipients] = new char[len+1];
	buffer[len] = '\0';
	strcpy(arr_address[count_addr_recipients], buffer);
	count_addr_recipients++;
	if(count_addr_recipients > 1)
		add_additional_recipients = 1; //этот параметр проверяется только в дествие Data
	return 1;
}

void MailTransaction::AddData(char *buffer, int len)
{
	if(len + current_size_data > size_data){
		char *tmp = new char[size_data+10];
		for(int i = 0; i<size_data;i++)
			tmp[i] = data[i];
		delete [] data;
		data = tmp;
		size_data = size_data + 10;
	}
	for(int i = 0;i < len; i++)
		data[i+current_size_data] = buffer[i];
	current_size_data += len;
	data[current_size_data] = '\0';

	//printf("%s\n", data);

}


void MailTransaction::AddToBufferIncompleteCRLF(const char* str)
{
	strcpy(buffer_incomplete_CRLF, str);
}


