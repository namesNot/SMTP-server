//#include "Parsing_RFC5322_Headers.h"


class ProcessingHeadersToRFC5322;

int MyStrchr(char *buffer, char ch, int len);
bool AllowQuotedPair(struct HeaderValueParseWorkset &ws);
bool ProcessingComment(char ch, struct HeaderValueParseWorkset &ws);
bool ProcessingQuotedString(struct HeaderValueParseWorkset &ws);
bool ProcessingAddress(char ch, struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses, int j);
bool CheckCharAtom(char ch);

int ProcessFoldingForAddressList(char ch, char *tmp_buffer, struct HeaderValueParseWorkset &ws, int &j);
bool CheckCorrectChar(char ch, struct HeaderValueParseWorkset &ws);
bool Group(struct HeaderValueParseWorkset &ws);
bool CorrectAddrSpec(struct HeaderValueParseWorkset &ws);
bool CorrectAddrSpec(struct HeaderValueParseWorkset &ws);
void AddSizeHeaderValueInfo(struct HeaderValueInfo &addresses);
bool ClassifyAddress( struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses);
bool ProcessingComma(struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses);
bool ProcessingComma(struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses);
bool ProcessingClosingGroup(struct HeaderValueParseWorkset &ws);
void SetState(char ch, struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses, int j);
bool ProcessDelimiter(char current_char, char *tmp_buffer, struct HeaderValueParseWorkset &ws, 
							struct HeaderValueInfo &addresses, int j);
char *ParseAddressHeaderField(const char *buffer, int& len, struct HeaderValueInfo &addresses);
bool TMPValidLocalChars(char *buffer, int pos);
bool ProcessingQuotedStringForLocalPart(char *buffer, int start_position, int &domain_part_start_position, int &local_part_lenght);
bool AnalyzeLocalPartForFields(char *buffer, int start_position, int &domain_part_start_position, int &local_part_lenght);
bool TMPValidDomainChars(char *buffer, int pos);
bool AnalyzeDomain(char *buffer, int domain_name_start_position, int &domain_part_lenght);
bool AnalyzeDomainPartForFields(char *buffer, int start_position, int &domain_part_lenght);
bool SearchNextNonWhitespaceChar(const char *buffer, int len, int start_pos, int &start_date, int &remaining_len);
bool ProcessingTwoNumber(const char ch1, const char ch2, char *numbers, int limit);
bool ProcessingFourNumber(const char ch1,const char ch2,const char ch3,const char ch4, char *numbers, bool (CheckNumb)(int));
bool CorrectYear(int numb);
bool TimeZone(int numb);
bool TimeOfDay(const char *buffer, int len, int &current_pos, int &remaining_len);
bool Month(const char *buffer);
bool ProcessingDayMonthYear(const char *buffer, int len, int &current_pos, int &remaining_len);
bool DayOfWeek(const char *buffer);
bool ProcessingDayOfWeek(const char *buffer, int len, int start_day_of_week, int &current_pos, int &remaining_len);
int CheckDayOfWeek(const char *buffer, int len, int &start_day_of_week, int &start_date, int &remaining_len);
bool DateTime(const char *buffer, int len);
char *SeparateUnfoldingHeader(const char *buffer, int& len);
bool ParsingMsgId(const char *buffer, int& len, struct HeaderValueInfo &addresses);
int ProcessingLocalAndDomainPartAddress(char *buffer, int start_position);
bool FieldFrom(char *buffer, int len_buffer, struct HeaderValueInfo &addresses);
bool FieldSender(char *buffer, int len_buffer, struct HeaderValueInfo &addresses);
 
bool FieldReplyTo(char *buffer, int len_buffer, struct HeaderValueInfo &addresses);
bool FieldToCcBcc(char *buffer, int len_buffer, struct HeaderValueInfo &addresses, ProcessingHeadersToRFC5322 &obj1,
							bool (ProcessingHeadersToRFC5323::*AddAddress)(char*, int));
bool MessageID(char *buffer, int len, struct HeaderValueInfo &addresses);
bool InReplyTo(char *buffer, int len, struct HeaderValueInfo &addresses);
bool References(char *buffer, int len, struct HeaderValueInfo &addresses);
bool AnalizeHeader(char *buffer, int read_count);
int FindNextHeaderField(const char *buffer, int len, int start_index_header, int &end_index_header);
int AddData(char *buffer, int len);
int FindEndOfMailData(char *buffer, int read_count);
int GetMessageForData();

