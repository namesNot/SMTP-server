
#include <gtest/gtest_prod.h>

class ProcessingHeadersToRFC5322{
	const char **from, **reply_to, *sender;
	const char *unfolding_from, *unfolding_sender, *unfolding_reply_to;
	int *len_addresses_from, *len_addresses_reply_to;
	int len_addresses_sender;
	int size_from, size_reply_to;
	int current_count_from, current_count_reply_to;

	const char *message_id, **in_reply_to, **references;
	const char *unfolding_message_id, *unfolding_in_reply_to, *unfolding_references;
	int len_addresses_message_id, *len_addresses_in_reply_to, *len_addresses_references;
	int size_in_reply_to, size_references;
	int current_count_in_reply_to, current_count_references;


	const char **to, **cc, **bcc;
	const char *unfolding_to, *unfolding_cc, *unfolding_bcc;
	int *len_addresses_to, *len_addresses_cc, *len_addresses_bcc;
	int size_to, size_cc, size_bcc;
	int current_count_to, current_count_cc, current_count_bcc;

	const char *orig_date;
	int len_date;

	const char *subject, *comments, *keywords;
	int len_subject, len_comments, len_keywords;


	const char **resent_from,  *resent_sender;
	const char *unfolding_resent_from, *unfolding_resent_sender;
	int *len_addresses_resent_from;
	int len_addresses_resent_sender;
	int size_resent_from;
	int current_count_resent_from;

	const char **resent_to, **resent_cc, **resent_bcc;
	const char *unfolding_resent_to, *unfolding_resent_cc, *unfolding_resent_bcc;
	int *len_addresses_resent_to, *len_addresses_resent_cc, *len_addresses_resent_bcc;
	int size_resent_to, size_resent_cc, size_resent_bcc;
	int current_count_resent_to, current_count_resent_cc, current_count_resent_bcc;

	const char *resent_message_id;
	const char *unfolding_resent_message_id;
	int len_addresses_resent_message_id;

	const char *resent_date;
	int len_resent_date;

private:
	ProcessingHeadersToRFC5322();
	~ProcessingHeadersToRFC5322(){};
	bool AddFrom(const char *value_header, int start_address, int len);
	bool AddSender(const char *value_header, int start_address, int len);
	bool AddReplyTo(const char *value_header, int start_address, int len);
	bool AddMessageID(const char *value_header, int start_address, int len);
	bool AddInReplyTo(const char *value_header, int start_address, int len);
	bool AddReferences(const char *value_header, int start_address, int len);
	bool AddDate(const char *address, int len);
	bool AddTo(const char *value_header, int start_address, int len);
	bool AddCc(const char *value_header, int start_address, int len);
	bool AddBcc(const char *value_header, int start_address, int len);
	bool AddSubject(const char *address, int len);
	bool AddComments(const char *address, int len);
	bool AddKeywords(const char *address, int len);
	bool AddResentDate(const char *address, int len);
	bool AddResentFrom(const char *value_header, int start_address, int len);
	bool AddResentSender(const char *value_header, int start_address, int len);
	bool AddResentTo(const char *value_header, int start_address, int len);
	bool AddResentCc(const char *value_header, int start_address, int len);
	bool AddResentBcc(const char *value_header, int start_address, int len);
	bool AddResentMessageID(const char *value_header, int start_address, int len);
	bool AnalyzeRelationshipOfHeaders();

	friend class MailTransaction;

	FRIEND_TEST(HeaderFromAndResentFrom, ProcessingHeaderTypesAndAddressSaving);
	FRIEND_TEST(HeaderSenderAndResentSender, ProcessingHeaderTypesAndAddressSaving);
	FRIEND_TEST(HeaderReplyTo, ProcessingHeaderTypesAndAddressSaving);

	FRIEND_TEST(HeaderToCcBcc, ProcessingHeaderTypesForToAndAddressSaving);
	FRIEND_TEST(HeaderToCcBcc, ProcessingHeaderTypesForCcAndAddressSaving);
	FRIEND_TEST(HeaderToCcBcc, ProcessingHeaderTypesForBccAndAddressSaving);

	FRIEND_TEST(HeaderMessageIDAndResentMessageID, ProcessingHeaderTypesAndAddressSaving);
	FRIEND_TEST(HeaderInReplyTo, ProcessingHeaderTypesAndAddressSaving);
	FRIEND_TEST(HeaderReferences, ProcessingHeaderTypesAndAddressSaving);
	FRIEND_TEST(DateTime, ProcessingHeaderAndAddressSaving);
	FRIEND_TEST(HeaderSubjectCommentsKeywords, CheckSavingHeader);

};

class MailTransaction{
	char *address_sender;
	int size_arr_address;
	int count_addr_recipients;
	char **arr_address;
	bool add_additional_recipients;

	char *buffer_incomplete_CRLF;
	int header_block_end_index;
	char *data;

	int size_data, current_size_data;
	int headers_block_end_index;
	char *tmp_buffer;
	
	bool CRLF_received;
	bool dot_received;
	bool CR_received;

	char *mail_data; //хранятся заголовки+тело сообщения по RFC5322
	int mail_data_max_size, mail_data_size;

	ProcessingHeadersToRFC5322 headers;

private:
	int MyStrchr(char *buffer, char ch, int len);
	bool AllowQuotedPair(struct HeaderValueParseWorkset &ws);
 	bool ProcessingComment(char ch, struct HeaderValueParseWorkset &ws);
	bool ProcessingQuotedString(struct HeaderValueParseWorkset &ws);
	bool ProcessingAddress(char ch, struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses, int index);
	bool CheckCharAtom(char ch);

	bool CheckCorrectChar(char ch, struct HeaderValueParseWorkset &ws);
	bool Group(struct HeaderValueParseWorkset &ws);
	bool CorrectAddrSpec(struct HeaderValueParseWorkset &ws);
	void AddSizeHeaderValueInfo(struct HeaderValueInfo &addresses);
	bool ClassifyAddress( struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses);
	bool ProcessingComma(struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses);
	bool ProcessingClosingGroup(struct HeaderValueParseWorkset &ws);
	void SetState(char ch, struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses, int index);
	bool ProcessDelimiter(char current_char, struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses, int index);

	bool ParseAddressHeaderField(const char *header,struct HeaderValueInfo &addresses);
	bool ValidLocalChars(const char *buffer, int pos);
 	bool ProcessingQuotedStringForLocalPart(const char *buffer, int start_position, int &domain_part_start_position, 
												int &local_part_lenght);
	bool AnalyzeLocalPartForFields(const char *buffer, int start_position, int &domain_part_start_position, 
												int &local_part_lenght);
	bool ValidDomainChars(const char *buffer, int pos);
	bool AnalyzeDomainLiteral(const char *buffer, int domain_name_start_position, int &domain_part_lenght);
	bool AnalyzeDomainPartForFields(const char *buffer, int start_position, int &domain_part_lenght);
	int SearchNextNonWhitespaceChar(const char *buffer, int &start_pos);
	bool ProcessingTwoNumber(const char ch1, const char ch2, char *numbers, int limit);
	bool ProcessingFourNumber(const char ch1,const char ch2,const char ch3,const char ch4, 
			char *numbers, bool (MailTransaction::*CheckNumb)(int));
	bool CorrectYear(int numb);
	bool TimeZone(int numb);
	bool TimeOfDay(const char *buffer, int &current_pos, int &remaining_len);
	bool Month(const char *buffer);
	bool ProcessingDayMonthYear(const char *buffer, int &current_pos, int &remaining_len);
	bool DayOfWeek(const char *buffer);
	bool ProcessingDayOfWeek(const char *buffer, int start_day_of_week, int &current_pos, int &remaining_len);
	int CheckDayOfWeek(const char *buffer, int &start_day_of_week, int &start_date, int &remaining_len);
	bool DateTime(const char *buffer, int len, ProcessingHeadersToRFC5322 &header, 
							bool (ProcessingHeadersToRFC5322::*AddAddress)(const char*, int));
	bool SeparateUnfoldingHeader(const char *header_line, char *unfolding_str, int& len_unfolding_str);
 	bool IdentificationFields(const char *buffer, struct HeaderValueInfo &addresses);
	int ProcessingLocalAndDomainPartAddress(const char *buffer, int start_position);
	bool HeaderFrom(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses);
	bool HeaderSender(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses);
 	bool HeaderReplyTo(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses);
	bool HeaderToCcBcc(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses,
			ProcessingHeadersToRFC5322 &header,bool (ProcessingHeadersToRFC5322::*AddAddress)(const char*,int, int));
	bool HeaderMessageID(const char *buffer, int len, struct HeaderValueInfo &addresses);
	bool HeaderInReplyTo(const char *buffer, int len, struct HeaderValueInfo &addresses);
	bool HeaderReferences(const char *buffer, int len, struct HeaderValueInfo &addresses);
	
	bool HeaderResentFrom(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses);
	bool HeaderResentSender(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses);

	bool HeaderResentToCcBcc(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses,
			ProcessingHeadersToRFC5322 &header, bool (ProcessingHeadersToRFC5322::*AddAddress)(const char*,int, int));

	bool HeaderResentMessageID(const char *buffer, int len, struct HeaderValueInfo &addresses);
	
	int AppendMailData(const char *buffer, int len); //изменил имя
	
	int AssignCodeToTheHeader(const char *header);
	bool ProcessingAddressHeaders(const char *unfolding_header_value, int read_count, struct HeaderValueInfo &addresses, int header_code);
	bool ProcessingIdentificationHeaders(const char *unfolding_header_value, int read_count, struct HeaderValueInfo &addresses, int header_code);
	bool ProcessingDateHeaders(const char *unfolding_header_value, int read_count, int header_code);

public:
	bool AnalizeHeader(int start_index, int read_count);
	int FindNextHeaderField(int start_index_header, int &end_index_header);
	int FindEndOfMailData(const char *buffer, int read_count);
	
public:
	MailTransaction();
	~MailTransaction(){ if(address_sender) delete [] address_sender;}
	void AddAddressSender(char *str, int len);
	bool AddAddressRecipients(char *buffer, int len);
	char *PrintSender(){return address_sender;}
	char *PrintRCPT(){return arr_address[0];}// удалить
	bool CheckAdditionalRecipients(){return add_additional_recipients; add_additional_recipients = 0; }
	void ResetAdditionalRecipient(){add_additional_recipients = 0;} // изменить на другое что то или имя
	void AddData(char *buffer, int len);
	int GetCurrentLenghtData(){return current_size_data;} // для чего
	int GetHeadersBlockEnd(){return headers_block_end_index;}
	void SetHeadersBlockEnd(int n){headers_block_end_index = n + current_size_data;}

	void AddToBufferIncompleteCRLF(const char *str);
	bool IsDataInBufferCRLF(){return buffer_incomplete_CRLF[0] != '\0'? true:false;};
	char *GetBufferCRLF(){return buffer_incomplete_CRLF;}
	int GetHeaderBlockEndPosition(){return header_block_end_index;}
	void SetHeaderBlockEndIndex(int n){header_block_end_index = n + current_size_data;}


	void ConvertToUppercase(char *header_field);

	friend class HeaderToCcBcc;

	
	FRIEND_TEST(AppendMailData, AddingData);
	FRIEND_TEST(AppendMailData, IncreasingTheMailBuffer);
	FRIEND_TEST(FindEndOfMailData, DetectsEndOfData);
	FRIEND_TEST(FindEndOfMailData_char_by_char, DetectsEndOfData);
	FRIEND_TEST(FindNextHeaderField, DetectsEndOfHeader);	
	FRIEND_TEST(SeparateUnfoldingHeader, CheckCorrectUnfolding); //это объявление не влияет на выполнение
	FRIEND_TEST(AnalyzeLocalPartForFields, CheckCorrectLocalPart);
	FRIEND_TEST(AnalyzeDomainPartForFields, CheckCorrectDomainPart);
	FRIEND_TEST(HeaderFromAndResentFrom, ProcessingHeaderTypesAndAddressSaving);
	FRIEND_TEST(HeaderSenderAndResentSender, ProcessingHeaderTypesAndAddressSaving);
	FRIEND_TEST(HeaderReplyTo, ProcessingHeaderTypesAndAddressSaving);
	FRIEND_TEST(HeaderToCcBcc, ProcessingHeaderTypesForToAndAddressSaving);
	FRIEND_TEST(HeaderToCcBcc, ProcessingHeaderTypesForCcAndAddressSaving);
	FRIEND_TEST(HeaderToCcBcc, ProcessingHeaderTypesForBccAndAddressSaving);
	FRIEND_TEST(HeaderMessageIDAndResentMessageID, ProcessingHeaderTypesAndAddressSaving);
	FRIEND_TEST(HeaderInReplyTo, ProcessingHeaderTypesAndAddressSaving);
	FRIEND_TEST(HeaderReferences, ProcessingHeaderTypesAndAddressSaving);
	FRIEND_TEST(DateTime, ProcessingHeaderAndAddressSaving);
	FRIEND_TEST(HeaderSubjectCommentsKeywords, CheckSavingHeader);
	FRIEND_TEST(ParseAddressHeaderField, CheckStructAddressList);
	FRIEND_TEST(IdentificationFields, CheckingStructureOfTheIdentificationField);
	
};


