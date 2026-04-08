#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <errno.h>

#include <cstdlib>

//#include "Parsing_RFC5322_Headers.h"


#define MAX_LEN_LOCAL_PART_ADDR 64 //delete
#define MAX_LEN_LABLE_DOMAIN 63 // dalete
#define MAX_LEN_DOMAIN 255 // delete
//имя поля:тело поля(символы+пробельные, кроме CR и LF внутри
//Фальцовка начинается с CRLF - пробел - символы)
//Квотрирование символов разрешено только в "string"
//Пробельные символы могут появляется между разными элементами в теле полей заголовков
//Комментарии так же включаются в тело поля(могут быть вложенныеми)
//Комментарии позволяют вкл в себя квотирование
//Комментарии являюся комментариями, если НЕ явл частью строки с квотированием
//FWS('\n'+" ") допускается между токетами в заголовке
//Нельзя использовать внутри atom, local-part вне ковычек, внутри домена
//
//Фальцованная строка не допускает еще одной фальцовки если не было символов ДО (?)
//Нельзя использовать фальцовку, если после нее идут только пробельные символы
//Почему нельзя писать (,),\ внутри ctext если например можно использовать вложенные комментарии
// В comments могут быть FWS, вложенные комментарии, экранирование и обычный текст
// CFWS превращается в один пробел между токенами


//FWS - \n + пробельный символ
//comments - комментарии в ()
//CFWS - места где можно ставить FWS и comments

// FWS = [*WSP CRLF] 1*WSP - между токетов [опционально ноль или более пробелов и CRLF] и обязательно 1 или более пробелов
/* ctext - все ASCII символы кроме (,),\*/
// Внутри комментария могут быть ctext, quoted-pair и comment(рекурсия)
// comment = "(" *([FWS] ccontent) [FWS] ")" - *([FWS] ccontent) 0 или более повторение(т.е. может быть пустой коммент)
// а в конце [FWS] говорит что между комментариями не обязательно пробелы
// И между вложенными комментариями, между словом и комментарием пробелы не нужны
// CFWS = (1*([FWS] comment) [FWS]) / FWS - это правило объясняет где разрешено использовать FWS и comment 
//
//Внутри ccontent обрабатывается только ctext/quoted-pair/comment, то есть например структура addr-spec никак не обрабатывается,
//а принимается как есть, без проверок

//quoted-pair = ("\\" (VCHAR / WSP))  - экранируем
//VCHAR -  символы от 33 до 126 и WSP


class ProcessingHeadersToRFC5322{
	char **from, **sender, **reply_to;
	int *len_addresses_from, *len_addresses_reply_to;
	int len_addresses_sender;
	int size_from, size_reply_to;
	int current_count_from, current_count_reply_to;

	char **message_id, **in_reply_to, **references;
	int len_addresses_message_id, *len_addresses_in_reply_to, *len_addresses_references;
	int size_in_reply_to, size_references;
	int current_count_in_reply_to, current_count_references;


	char **to, **cc, **bcc;
	int *len_addresses_to, *len_addresses_cc, *len_addresses_bcc;
	int size_to, size_cc, size_bcc;
	int current_count_to, current_count_cc, current_count_bcc;

	char **orig_date;
	int len_date;

	char **subject, **comments, **keywords;
	int len_subject, len_comments, len_keywords;

	char **resent_date;
	int len_resent_date;



public:
	ProcessingHeadersToRFC5322();
	~ProcessingHeadersToRFC5322(){};
	bool AddFrom(char *address, int len);
	void PrintFrom();	
	bool AddSender(char *address, int len);
	void PrintSender();
	bool AddReplyTo(char *address, int len);
	void PrintReplyTo();
	bool AddMessageID(char *address, int len);
	void PrintMessageID();
	bool AddInReplyTo(char *address, int len);
	void PrintInReplyTo();
	bool AddReferences(char *address, int len);
	void PrintReferences();
	bool AddDate(char *address, int len);
	void PrintDate();
	bool AddTo(char *address, int len);
	bool AddCc(char *address, int len);
	bool AddBcc(char *address, int len);
	void PrintTo();	
	void PrintCc();	
	void PrintBcc();

	bool AddSubject(char *address, int len);
	void PrintSubject();
	bool AddComments(char *address, int len);
	void PrintComments();	
	bool AddKeywords(char *address, int len);
	void PrintKeywords();

	bool AddResentDate(char *address, int len);
	void PrintResentDate();


	bool AnalyzeRelationshipOfHeaders();


}obj;

bool ProcessingHeadersToRFC5322::AnalyzeRelationshipOfHeaders()
{
	if(from == NULL || orig_date == NULL) //обязательные поля
		return 0;

	if(current_count_from > 1){ //проверка наличия sender если from > 1
		if(sender == NULL)
			return 0;
	}

	return 1;
}

ProcessingHeadersToRFC5322::ProcessingHeadersToRFC5322()
{ 
	from = sender = reply_to = NULL; 
	len_addresses_from  = len_addresses_reply_to = NULL;
	len_addresses_sender = 0;
	size_from = size_reply_to = 0;  
	current_count_from = current_count_reply_to = 0;

	message_id = in_reply_to = references= NULL;
	len_addresses_message_id = 0;
	len_addresses_in_reply_to = len_addresses_references = NULL;
	size_in_reply_to = size_references= 0;
	current_count_in_reply_to = current_count_references = 0;
	
	to = cc = bcc = NULL;
	len_addresses_to = len_addresses_cc = len_addresses_bcc = NULL;
	size_to = size_cc = size_bcc = 0;
	current_count_to = current_count_cc = current_count_bcc = 0;

	orig_date = NULL;
	len_date = 0;

	subject = comments = keywords = NULL;
	len_subject = len_comments = len_keywords = 0;

	resent_date = NULL;
	len_resent_date = 0;

}

bool ProcessingHeadersToRFC5322::AddFrom(char *address, int len)
{
	if(size_from == 0){
		from = new char*[5];
		len_addresses_from = new int[5];
		size_from = 5;
	}
	else if(size_from == current_count_from){
		char **tmp = new char*[size_from + 5];
		int *tmp_len = new int[size_from + 5];
		for(int i=0; i < size_from; i++){
			tmp[i] = from[i];
			tmp_len[i] = len_addresses_from[i];
		}
		delete [] from;
		delete [] len_addresses_from;
		from = tmp;
		len_addresses_from = tmp_len;
		size_from = size_from + 5;
	}

	from[current_count_from] = address;
	len_addresses_from[current_count_from] = len;
	current_count_from++;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintFrom()
{
	for(int i=0;i<current_count_from; i++){
		write(1,from[i], len_addresses_from[i]);
		puts("");
	}
}

bool ProcessingHeadersToRFC5322::AddSender(char *address, int len)
{
	if(sender == NULL){
		sender = new char*;
	}
	else{
		return 0;
	}

	*sender = address;
	len_addresses_sender = len;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintSender()
{
	write(1,*sender, len_addresses_sender);
	puts("");
}

bool ProcessingHeadersToRFC5322::AddReplyTo(char *address, int len)
{
	if(size_reply_to == 0){
		reply_to = new char*[5];
		len_addresses_reply_to = new int[5];
		size_reply_to = 5;
	}
	else if(size_reply_to == current_count_reply_to){
		char **tmp = new char*[size_reply_to + 5];
		int *tmp_len = new int[size_reply_to + 5];
		for(int i=0; i < size_reply_to; i++){
			tmp[i] = reply_to[i];
			tmp_len[i] = len_addresses_reply_to[i];
		}
		delete [] reply_to;
		delete [] len_addresses_reply_to;
		reply_to = tmp;
		len_addresses_reply_to = tmp_len;
		size_reply_to = size_reply_to + 5;
	}

	reply_to[current_count_reply_to] = address;
	len_addresses_reply_to[current_count_reply_to] = len;
	current_count_reply_to++;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintReplyTo()
{
	for(int i=0;i<current_count_from; i++){
		write(1,from[i], len_addresses_from[i]);
		puts("");
	}
}

bool ProcessingHeadersToRFC5322::AddMessageID(char *address, int len)
{
	if(message_id == NULL){
		message_id = new char*;
	}
	else{
		return 0;
	}

	*message_id = address;
	len_addresses_message_id = len;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintMessageID()
{
	write(1,*message_id, len_addresses_message_id);
	puts("");
}

bool ProcessingHeadersToRFC5322::AddInReplyTo(char *address, int len)
{
	if(size_in_reply_to == 0){
		in_reply_to = new char*[5];
		len_addresses_in_reply_to = new int[5];
		size_in_reply_to = 5;
	}
	else if(size_in_reply_to == current_count_in_reply_to){
		char **tmp = new char*[size_in_reply_to + 5];
		int *tmp_len = new int[size_in_reply_to + 5];
		for(int i=0; i < size_in_reply_to; i++){
			tmp[i] = in_reply_to[i];
			tmp_len[i] = len_addresses_in_reply_to[i];
		}
		delete [] in_reply_to;
		delete [] len_addresses_in_reply_to;
		in_reply_to = tmp;
		len_addresses_in_reply_to = tmp_len;
		size_in_reply_to = size_in_reply_to + 5;
	}

	in_reply_to[current_count_in_reply_to] = address;
	len_addresses_in_reply_to[current_count_in_reply_to] = len;
	current_count_in_reply_to++;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintInReplyTo()
{
	for(int i=0;i<current_count_in_reply_to; i++){
		write(1,in_reply_to[i], len_addresses_in_reply_to[i]);
		puts("");
	}
}

bool ProcessingHeadersToRFC5322::AddReferences(char *address, int len)
{
	if(size_references == 0){
		references = new char*[5];
		len_addresses_references = new int[5];
		size_references = 5;
	}
	else if(size_references == current_count_references){
		char **tmp = new char*[size_references + 5];
		int *tmp_len = new int[size_references + 5];
		for(int i=0; i < size_references; i++){
			tmp[i] = references[i];
			tmp_len[i] = len_addresses_references[i];
		}
		delete [] references;
		delete [] len_addresses_references;
		references = tmp;
		len_addresses_references = tmp_len;
		size_references = size_references + 5;
	}

	references[current_count_references] = address;
	len_addresses_references[current_count_references] = len;
	current_count_references++;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintReferences()
{
	for(int i=0;i<current_count_references; i++){
		write(1,references[i], len_addresses_references[i]);
		puts("");
	}
}

bool ProcessingHeadersToRFC5322::AddDate(char *address, int len)
{
	if(orig_date == NULL){
		orig_date = new char*;
	}
	else{
		return 0;
	}

	*orig_date = address;
	len_date = len;
	return 1;
}

void ProcessingHeadersToRFC5322::PrintDate()
{	
		write(1,*orig_date, len_date);
		puts("");
}

bool ProcessingHeadersToRFC5322::AddTo(char *address, int len)
{
	if(size_to == 0){
		to = new char*[5];
		len_addresses_to = new int[5];
		size_to = 5;
	}
	else if(size_to == current_count_to){
		char **tmp = new char*[size_to + 5];
		int *tmp_len = new int[size_to + 5];
		for(int i=0; i < size_to; i++){
			tmp[i] = to[i];
			tmp_len[i] = len_addresses_to[i];
		}
		delete [] to;
		delete [] len_addresses_to;
		to = tmp;
		len_addresses_to = tmp_len;
		size_to = size_to + 5;
	}

	to[current_count_to] = address;
	len_addresses_to[current_count_to] = len;
	current_count_to++;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintTo()
{
	for(int i=0;i<current_count_to; i++){
		write(1,to[i], len_addresses_to[i]);
		puts("");
	}
}

bool ProcessingHeadersToRFC5322::AddCc(char *address, int len)
{
	if(size_cc == 0){
		cc = new char*[5];
		len_addresses_cc = new int[5];
		size_cc = 5;
	}
	else if(size_cc == current_count_cc){
		char **tmp = new char*[size_cc + 5];
		int *tmp_len = new int[size_cc + 5];
		for(int i=0; i < size_cc; i++){
			tmp[i] = cc[i];
			tmp_len[i] = len_addresses_cc[i];
		}
		delete [] cc;
		delete [] len_addresses_cc;
		cc = tmp;
		len_addresses_cc = tmp_len;
		size_cc = size_cc + 5;
	}

	cc[current_count_cc] = address;
	len_addresses_cc[current_count_cc] = len;
	current_count_cc++;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintCc()
{
	for(int i=0;i<current_count_cc; i++){
		write(1,cc[i], len_addresses_cc[i]);
		puts("");
	}
}

bool ProcessingHeadersToRFC5322::AddBcc(char *address, int len)
{
	if(size_bcc == 0){
		bcc = new char*[5];
		len_addresses_bcc = new int[5];
		size_bcc = 5;
	}
	else if(size_bcc == current_count_bcc){
		char **tmp = new char*[size_bcc + 5];
		int *tmp_len = new int[size_bcc + 5];
		for(int i=0; i < size_bcc; i++){
			tmp[i] = bcc[i];
			tmp_len[i] = len_addresses_bcc[i];
		}
		delete [] bcc;
		delete [] len_addresses_bcc;
		bcc = tmp;
		len_addresses_bcc = tmp_len;
		size_bcc = size_bcc + 5;
	}

	bcc[current_count_bcc] = address;
	len_addresses_bcc[current_count_bcc] = len;
	current_count_bcc++;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintBcc()
{
	for(int i=0;i<current_count_bcc; i++){
		write(1,bcc[i], len_addresses_bcc[i]);
		puts("");
	}
}

bool ProcessingHeadersToRFC5322::AddSubject(char *address, int len)
{
	if(subject == NULL){
		subject = new char*;
	}
	else{
		return 0;
	}

	*subject = address;
	len_subject = len;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintSubject()
{
	write(1,*subject, len_subject);
	puts("");
}


bool ProcessingHeadersToRFC5322::AddComments(char *address, int len)
{
	if(comments == NULL){
		comments = new char*;
	}
	else{
		return 0;
	}

	*comments = address;
	len_comments = len;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintComments()
{
	write(1,*comments, len_comments);
	puts("");
}

bool ProcessingHeadersToRFC5322::AddKeywords(char *address, int len)
{
	if(keywords == NULL){
		keywords = new char*;
	}
	else{
		return 0;
	}

	*keywords = address;
	len_keywords = len;

	return 1;
}

void ProcessingHeadersToRFC5322::PrintKeywords()
{
	write(1,*keywords, len_keywords);
	puts("");

}

bool ProcessingHeadersToRFC5322::AddResentDate(char *address, int len)
{
	if(resent_date == NULL){
		resent_date = new char*;
	}
	else{
		return 0;
	}

	*resent_date = address;
	len_resent_date = len;
	return 1;
}

void ProcessingHeadersToRFC5322::PrintResentDate()
{	
		write(1,*resent_date, len_resent_date);
		puts("");
}

struct HeaderValueParseWorkset{
	const char *CRLF = "\r\n";
	int pos_in_CRLF = 0, len_CRLF = 2, open_comment_count = 0, result = 0;
	bool has_non_whitespace = false, has_opening_quote = false;

	// показывает какой объект разбирается в данный момент
	bool quoted_pair = false, atom = true, comment = false, quoted_string = false, name_addr = false, group = false;
	//показывает какие объекты были в каждом mailbox
	bool was_comment = false, was_atom = false, was_quoted_string = false, was_name_addr = false;

	bool mailbox_started = false, potentially_invalid_char = false, special_char = false, comma_required = false;
};

enum AddressKind {GROUP = 0, NAME_ADDR, ADDR_SPEC};

struct HeaderValueInfo{
	enum AddressKind *kinds = NULL;
	int *start_pos = NULL;
	int address_count = 0, address_max_size = 0;
};

int MyStrchr(char *buffer, char ch, int len)
{
	for(int i=0;i<len;i++){
		if(buffer[i] == ch)
			return i;
	}
	return -1;
}

bool AllowQuotedPair(struct HeaderValueParseWorkset &ws)
{
	if(ws.atom || ws.name_addr) 
		return 0;
	ws.quoted_pair = true;
	return 1; 
}

bool ProcessingComment(char ch, struct HeaderValueParseWorkset &ws)
{
	if(ws.quoted_string || ws.quoted_pair || ws.name_addr)
		return 1;

	if(ch == '('){
		ws.open_comment_count++;
		ws.atom =  false;
		ws.comment = true;
	}
	else if(ch == ')'){
		ws.open_comment_count--;
		if(ws.open_comment_count < 0)	
			return 0;
	}
	return 1;
}

bool ProcessingQuotedString(struct HeaderValueParseWorkset &ws)
{
	if(ws.quoted_pair || ws.comment || ws.name_addr)
		return 1;
	if(ws.quoted_string == false){
		ws.atom = false;
		ws.has_opening_quote = ws.quoted_string = true;
	}
	else if(ws.quoted_string){
		ws.has_opening_quote = false;
	}
	
	return 1;
}

bool ProcessingAddress(char ch, struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses, int j)
{
	if(ws.quoted_pair || ws.comment || ws.quoted_string)
		return 1; //не обрабатываем

	if(ch == '<'){
		if(ws.name_addr || ws.was_name_addr)
			return 0;
		ws.atom = false;
		ws.name_addr = true;
		addresses.start_pos[addresses.address_count] = j;
	}

	//проверка на > без <
	if(ch == '>' && !ws.name_addr)
		return 0;
	return 1;
}

bool CheckCharAtom(char ch)
{
	//условия с (,),<,>,:,;,',', нельзя убрать, так как при использовании квотрирования эти символы будут допускаться
	//пример: hel(lo <mail@dom.ru>
	if(ch == '(' || ch == ')')
		return 0;
	else if(ch == '<' || ch == '>')
		return 0;
	else if( ch == '[' || ch == ']')
		return 0;
	else if( ch == ':' || ch == ';')
		return 0;
	else if( ch == '@' || ch == '\\')
		return 0;
	else if(ch == ',' || ch == '.')
		return 0;

	return 1;
}

int ProcessFoldingForAddressList(char ch, char *tmp_buffer, struct HeaderValueParseWorkset &ws, int &j)
{
	if(ch == ws.CRLF[ws.pos_in_CRLF]){
		ws.pos_in_CRLF++;
		return 1; //continue
	}
	if(ws.pos_in_CRLF == ws.len_CRLF){
		if(!ws.has_non_whitespace){
			return -1;
		}
		ws.has_non_whitespace = false;
		tmp_buffer[j] = ' ';
		j++;
		ws.pos_in_CRLF = 0;
		return 1; //continue
	}
	if(ch == '\n' || ws.pos_in_CRLF != 0){
		return -1;
	}

	return 0;
}

bool CheckCorrectChar(char ch, struct HeaderValueParseWorkset &ws)
{
	if(ws.special_char){
		return 1;
	}

	if((ch > 32 && ch < 127) || ch == 32 || ch == 9){
		if(ws.atom){
			if(CheckCharAtom(ch) == 0){
				ws.potentially_invalid_char = true;
				return 1;
			}
			ws.was_atom = true;
		}
		else if(ws.comment){
			if(ws.open_comment_count == 0){
				ws.comment = false;
				ws.was_comment = ws.atom = true;
			}	
		}
		else if(ws.quoted_string){
			if(ch == '\"' && !ws.has_opening_quote){
				ws.quoted_string = false;
				ws.was_quoted_string = ws.atom = true;
			}
		}
		else if(ws.name_addr){
			if(ch == '>'){
				ws.name_addr = false;
				ws.was_name_addr = ws.atom = true;
			}
		}
		return 1;
	}
	return 0;
}



bool Group(struct HeaderValueParseWorkset &ws)
{
	if(ws.comment || ws.quoted_string || ws.quoted_pair /*|| ws.addr_spec*/ || ws.name_addr)
		return 1;
	//ws.atom = false;
	//состояние остается atom
	if(ws.group)
		return 0;
	ws.special_char = ws.group = true;
	if(!ws.was_name_addr && !ws.was_comment && (ws.was_atom || ws.was_quoted_string)){
		ws.was_comment = ws.was_atom = ws.was_quoted_string = ws.was_name_addr = ws.mailbox_started = false;
		return 1;
	}

	return 0;
}


bool CorrectAddrSpec(struct HeaderValueParseWorkset &ws)
{
	if(!ws.was_comment && (ws.was_atom || ws.was_quoted_string)){
		return true;
	}
	return false;
}
void AddSizeHeaderValueInfo(struct HeaderValueInfo &addresses)
{
	enum AddressKind *tmp = new enum AddressKind[addresses.address_max_size + 5];
	int *tmp_start_positions = new int[addresses.address_max_size + 5];

	for(int i=0; i < addresses.address_count; i++){
		tmp[i] = addresses.kinds[i];
		tmp_start_positions[i] = addresses.start_pos[i];
	}
	delete [] addresses.kinds;
	delete [] addresses.start_pos;

	addresses.address_max_size = addresses.address_max_size + 5;
	addresses.kinds = tmp;
	addresses.start_pos = tmp_start_positions;
}

bool ClassifyAddress( struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses)
{
	if(!ws.was_name_addr){ //addr_spec
		if(!CorrectAddrSpec(ws)){
			return false;
		}
		addresses.kinds[addresses.address_count] = ADDR_SPEC;
		addresses.address_count++;
	}
	else{ //if(was_name_addr)
		if(ws.potentially_invalid_char){
			return false;
		}
		addresses.kinds[addresses.address_count] = NAME_ADDR;
		addresses.address_count++;
	}
	return true;
}


bool ProcessingComma(struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses)
{
	if(ws.comment || ws.quoted_string || ws.name_addr || ws.quoted_pair)
		return 1;
	if(ws.mailbox_started == false){
		return 0;
	}
	ws.mailbox_started = false;
	
	if(ClassifyAddress(ws, addresses) == false){
		return 0;
	}
	ws.potentially_invalid_char = ws.comma_required = false;
	ws.was_comment = ws.was_atom = ws.was_quoted_string = ws.was_name_addr = false;
	ws.special_char = true;

	return 1;
}

bool ProcessingClosingGroup(struct HeaderValueParseWorkset &ws)
{
	if(ws.comment || ws.quoted_string || ws.quoted_pair || ws.name_addr)
		return 1;
	if(ws.mailbox_started == false || !ws.group)
		return 0;

	//ws.need_comma = true;
	ws.group = false;
	ws.special_char = true;
	return 1;
}

void SetState(char ch, struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses, int j)
{
	ws.has_non_whitespace = true;
	if(!ws.special_char && !ws.mailbox_started){	
		ws.mailbox_started = true;
		addresses.start_pos[addresses.address_count] = j;
	}
	if(ws.special_char){
		if(ch == ';')
			ws.comma_required = true;
	}
	ws.special_char = false;
}

bool ProcessDelimiter(char current_char, char *tmp_buffer, struct HeaderValueParseWorkset &ws, 
										struct HeaderValueInfo &addresses, int j)
{
	if(current_char == '(' || current_char == ')'){
		if(ProcessingComment(current_char, ws) == false){
			return false;
		}
	}
	else if(current_char == '\"'){
		ProcessingQuotedString(ws);
		return true;
	}
	else if(current_char == '<' || current_char == '>'){
		if(ProcessingAddress(current_char, ws, addresses, j) == false){
			return false;
		}
	}
	else if(current_char == ','){
		if(ProcessingComma(ws, addresses) == false){	
			return false;
		}
	}
	else if(current_char == ':'){
		if(Group(ws) == false){
			return false;
		}
		addresses.kinds[addresses.address_count] = GROUP;
		addresses.address_count++;
	}
	else if(current_char == ';'){
		if(ProcessingClosingGroup(ws) == false){
			return false;
		}
	}

	return true;
}


//QUOTED_PAIR НЕ РАБОТАЕТ С UTF-8 РАЗОБРАТЬСЯ!!!
char *ParseAddressHeaderField(const char *buffer, int& len, struct HeaderValueInfo &addresses)
{
	int j = 0; //текущая длина расфальцованного буфера
	char current_char;
	struct HeaderValueParseWorkset ws;
	char *tmp_buffer = new char[len];

	for(int i = 0; i < len; i++){
		current_char = buffer[i];

		if((ws.result = ProcessFoldingForAddressList(current_char, tmp_buffer, ws, j)) == 1)
			continue;
		else if(ws.result == -1){ delete [] tmp_buffer; return NULL;}
		
		if(addresses.address_count == addresses.address_max_size){
			AddSizeHeaderValueInfo(addresses);
		}

		// квотрирование символа 
		if(current_char == '\\' && !ws.quoted_pair){ //!ws.quoted_pair чтобы квотрировать символ '\'
			if(AllowQuotedPair(ws)){
				continue;
			}
			delete [] tmp_buffer;
			return NULL;
		}
		
		if(ProcessDelimiter(current_char, tmp_buffer, ws, addresses, j) == 0){
			delete [] tmp_buffer;
			return NULL;
		}
		
		//проверка допустимых символов
		if(CheckCorrectChar(current_char,ws) == 0){
			delete [] tmp_buffer;
			return NULL;
		}

		//если при требовании получения запятой дошли до сюда, то запятой не было или она квотрирована
		if(ws.comma_required){
			delete [] tmp_buffer;
			return NULL;
		}
		
		if(current_char != ' ' && current_char != 9){
			SetState(current_char, ws, addresses, j);		
		}
		ws.quoted_pair = false;

		tmp_buffer[j] = current_char;
		j++;
	}
	
	if(ClassifyAddress(ws, addresses) == false){
		delete [] tmp_buffer;
		return NULL;
	}
	if(ws.open_comment_count || ws.quoted_pair || ws.quoted_string || ws.name_addr || !ws.mailbox_started || ws.group){
		delete [] tmp_buffer;
		return NULL;
	}
	tmp_buffer[j] = '\r';
	tmp_buffer[j+1] = '\n';
	len = j+2;
	return tmp_buffer;
}




//удалить
bool TMPValidLocalChars(char *buffer, int pos)
{
//!(33) #(35) %(36) %(37) &(38) '(39) *(42) +(43) -(45) /(47) =(61) ?(63) ^(94) _(95) `(96) {(123) |(124) }(125) ~(126)
	if(buffer[pos] == 33)
		return 1;
	else if(buffer[pos] >= 35 && buffer[pos] <= 39)
		return 1;	
	else if(buffer[pos] == 42 || buffer[pos] == 43)
		return 1;
	else if(buffer[pos] == 45 || buffer[pos] == 47)
		return 1;
	else if(buffer[pos] == 61 || buffer[pos] == 63)
		return 1;
	else if(buffer[pos] >= 94 && buffer[pos] <= 96)
		return 1;
	else if(buffer[pos] >=123 && buffer[pos] <= 126)
		return 1;
	else if(buffer[pos] >=65 && buffer[pos] <=90)
		return 1;
	else if(buffer[pos] >=97 && buffer[pos] <=122)
		return 1;
	 else if(buffer[pos] >=48 && buffer[pos] <=57)
		return 1;
	return 0;
}


bool ProcessingQuotedStringForLocalPart(char *buffer, int start_position, int &domain_part_start_position, int &local_part_lenght)
{
	bool quoted_string = false, closed_quoted_string = false, quoted_pair = false, str_received = false;
	for(int i = start_position; buffer[i] != '\r'; i++){
		if(buffer[i] == '@' && !quoted_string){
			if(!str_received)
				return false;
			local_part_lenght = i - start_position;
			domain_part_start_position = start_position + local_part_lenght + 1;
			return true;
		}
		if(buffer[i] == '\\')
			quoted_pair = true;

		if(buffer[i] == '"' && !quoted_pair){
			if(quoted_string){
				quoted_string = false;
				closed_quoted_string = true;
				continue;
			}
			//если закрыт quoted_string, то
			else if(closed_quoted_string){
				return false;
			}
			quoted_string  = true;
			continue;
		}

		if((buffer[i] > 32 && buffer[i] < 127) || buffer[i] == 32 || buffer[i] == 9){
			if(!quoted_string)
			       return false;	
			str_received = true;

			quoted_pair = false; //что лучше: постоянно заносить значение или делать проверку
		}
	}
	return false;
}

bool AnalyzeLocalPartForFields(char *buffer, int start_position, int &domain_part_start_position, int &local_part_lenght)
{
	bool char_reseived = false, dot_received = false; 

	local_part_lenght = 0;

	if(buffer[start_position] == '"'){
		if(ProcessingQuotedStringForLocalPart(buffer, start_position, domain_part_start_position, local_part_lenght) == 0)
			return false;
		return true;
	}
	if(buffer[start_position] == '.' )
		return 0;
	for(int i=start_position; buffer[i] != '\r'; i++){ //условие продолжение можно заменить на true
		if(buffer[i] == '.'){
			if(dot_received)
				return 0;
			dot_received = true;
			local_part_lenght++;
			continue;
		}
		if(buffer[i] == '@'){
			if(dot_received || char_reseived == false)
				return 0;
			domain_part_start_position = i+1;
			local_part_lenght;
					     
			if(local_part_lenght > MAX_LEN_LOCAL_PART_ADDR)
				return 0;
			return 1;
		}
		if(TMPValidLocalChars(buffer,i)){
			local_part_lenght++;
			char_reseived = true;
			dot_received = false;
			continue;
		}
		break;
	}
	
	return 0;
}

bool TMPValidDomainChars(char *buffer, int pos)
{
	if(buffer[pos] >= 48 && buffer[pos] <= 57){
		return 1;
	}
	if(buffer[pos] >= 65 && buffer[pos] <= 90){
		return 1;
	}
	if(buffer[pos] >= 97 && buffer[pos] <= 122){
		return 1;
	}

	return 0;
}


bool AnalyzeDomain(char *buffer, int domain_name_start_position, int &domain_part_lenght)
{	
	int max_digits_per_octet = 3; //ограничивает кол-во цифр в одном октете xxx.xxx.xxx.xxx
	int max_dots_in_ip_addr = 3; // ограничивает кол-во октетов в ip-адресе
	int current_count_digits = 0, current_count_dots = 0;
	bool first_digit_received = 0;
	char current_char;
	int i;

	const char dot_symbol = 46;


	//if(buffer[domain_name_start_position] != '[') // Если здесь нет ip-адрес, то считаю что адрес корректный
	//		return 1;
	domain_part_lenght++;
	
	for(i=domain_name_start_position+1; buffer[i] != ']'; i++){
		current_char = buffer[i];
		
		if(current_char == '[' || ((current_char < 47 || current_char > 58) && current_char != dot_symbol))
			return 0;

		if(current_char == dot_symbol){
			current_count_dots++;
			if(current_count_dots > max_dots_in_ip_addr || first_digit_received == 0)
				return 0;
			domain_part_lenght++;
			current_count_digits = first_digit_received = 0;
			continue;
		}

		if(first_digit_received == 0)
			first_digit_received = 1;

		current_count_digits++;

		if(current_count_digits > max_digits_per_octet)
			return 0;

		domain_part_lenght++;
	}
	
	if(current_count_dots != max_digits_per_octet || current_count_digits == 0) 
		return 0;
	domain_part_lenght++;
	
	i++;
	if(buffer[i] != ',' && buffer[i] != ';' && buffer[i] != '\r' && buffer[i] != '>')
	       return 0;
	if(buffer[i] == '>')
	       i++;	
	for(i=i+1; buffer[i] != ' ' && buffer[i] != 9; i++){}

	if((buffer[i] != '\r') && (buffer[i] != ',') && (buffer[i] != ';'))
		return 0;

	return 1;
}


bool AnalyzeDomainPartForFields(char *buffer, int start_position, int &domain_part_lenght)
{
	int i, lable_lenght = 0;
	bool new_label_received = false, FQDN_detected = false, space_received = false;
	
	domain_part_lenght = 0;

	//Проверяем на форму адреса вида [x.x.x.x]
	if(buffer[start_position] == '['){
		if(AnalyzeDomain(buffer, start_position, domain_part_lenght) == 0)
			return 0;

		return 1;
	}
	
	for(i=start_position; buffer[i] != ',' && buffer[i] != ';' && buffer[i] != '\r' && buffer[i] != '>'; i++){	
		if(buffer[i] == ' ' || buffer[i] == 9){
				space_received = true; //рассчитываю что это пробелы после адреса и до ,;\r или >
				continue;
		}
		if(TMPValidDomainChars(buffer, i)){
			if(space_received){ //если после таких пробелов есть символы, то это ошибка
				return 0;
			}
			lable_lenght++;
			if(lable_lenght >= MAX_LEN_LABLE_DOMAIN)
				return 0;
			if(new_label_received  == false)
				new_label_received = true;
			continue;
		}
		if(buffer[i] == 45){// 45(-)
			if(new_label_received == false)
				return 0;
			lable_lenght++;
			continue;
		}

		if(buffer[i] == '.'){
			if(new_label_received == false)
				return 0;
			new_label_received = false;
			FQDN_detected = true; // т.е. получили первую корректную точку, а значит домен будет корректен
			domain_part_lenght += (lable_lenght + 1);
			lable_lenght = 0;
			continue;
		}
		
		return 0;
	}

	if(new_label_received == false || FQDN_detected == false)
		return 0;
	
	if(buffer[i] == '>'){
		for(i=i+1; buffer[i] == ' ' || buffer[i] == 9; i++){}
		if((buffer[i] != '\r') && (buffer[i] != ',') && (buffer[i] != ';') && (buffer[i] != '<'))
			return 0;
	}

	domain_part_lenght += lable_lenght;

	return 1;
}


bool SearchNextNonWhitespaceChar(const char *buffer, int len, int start_pos, int &start_date, int &remaining_len)
{
	int j=0;
	for(int i = start_pos; true; i++, j++){
		if(i == len)
			return 0;
		if(buffer[i] != ' ' && buffer[i] != 9){
			start_date = i;
			remaining_len -= j;
			break;
		}
	}
	return 1;
}




bool ProcessingTwoNumber(const char ch1, const char ch2, char *numbers, int limit)
{
	int number = 0;
	if((ch1 > 57 || ch1 < 48) || (ch2 > 57 || ch2 < 48))
		return 0;
	numbers[0] = ch1;
	numbers[1] = ch2;
	numbers[2] = '\0';
	number = (int)strtol(numbers, NULL, 10);
	if(number > limit)
		return 0;
	return 1;
}


bool ProcessingFourNumber(const char ch1,const char ch2,const char ch3,const char ch4, char *numbers, bool (CheckNumb)(int))
{
	int number = 0;

	if((ch1 > 57 || ch1 < 48) || (ch2 > 57 || ch2 < 48) || (ch3 > 57 || ch3 < 48) || (ch4 > 57 || ch4 < 48))
		return 0;
	numbers[0] = ch1;
	numbers[1] = ch2;
	numbers[2] = ch3;
	numbers[3] = ch4;
	numbers[4] = '\0';
	number = (int)strtol(numbers, NULL, 10);
	if(CheckNumb(number) == 0)
		return 0;
	return 1;
}

bool CorrectYear(int numb)
{
	if(numb < 1900)
		return 0;
	return 1;
}

bool TimeZone(int numb)
{
	if(numb > 2359)
		return 0;
	return 1;
}



bool TimeOfDay(const char *buffer, int len, int &current_pos, int &remaining_len)
{
	char *numbers = new char[5];

	if(SearchNextNonWhitespaceChar(buffer, len, current_pos, current_pos, remaining_len) == 0){
		delete [] numbers;
		return 0;
	}

	if(remaining_len < 5)// чч:мм
			return 0;

	if(ProcessingTwoNumber(buffer[current_pos], buffer[current_pos+1], numbers, 23) == 0){
		delete [] numbers;
		return 0;
	}
	if(buffer[current_pos+2] != ':'){
		delete [] numbers;
		return 0;
	}
	remaining_len -=3;
	current_pos +=3;

	if(ProcessingTwoNumber(buffer[current_pos], buffer[current_pos+1], numbers, 59) == 0){
		delete [] numbers;
		return 0;
	}

	remaining_len -=2;
	current_pos +=2;

	if(buffer[current_pos] == ':'){
		current_pos+=1;	
		remaining_len -=1;

		if(remaining_len < 2)
			return 0;
		if(ProcessingTwoNumber(buffer[current_pos], buffer[current_pos+1], numbers, 59) == 0){
			delete [] numbers;
			return 0;
		}
		current_pos +=2;
		remaining_len -=2;
	}

	if(buffer[current_pos] != ' ' && buffer[current_pos] != 9){
		delete [] numbers;
		return 0;
	}
	current_pos +=1;
	remaining_len -=1;


	if(SearchNextNonWhitespaceChar(buffer, len, current_pos, current_pos, remaining_len) == 0)
		return 0;

	if(buffer[current_pos] != '+' && buffer[current_pos] != '-')
	       return 0;
	current_pos +=1;
	remaining_len -=1;

	if(remaining_len < 4)
			return 0;
	if(ProcessingFourNumber(buffer[current_pos],buffer[current_pos+1],buffer[current_pos+2],buffer[current_pos+3], 
				numbers, &TimeZone) == 0){
		delete [] numbers;
		return 0;
	}
	delete [] numbers;
	
	remaining_len -=4;
	current_pos +=4;
	
	return 1;
}

bool Month(const char *buffer)
{
	if(strncmp(buffer, "Jan", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Feb", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Mar", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Apr", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "May", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Jun", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Jul", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Aug", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Sep", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Oct", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Nov", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Dec", 3) == 0)
		return 1;	
	
	return 0;
}


bool ProcessingDayMonthYear(const char *buffer, int len, int &current_pos, int &remaining_len)
{
	char *numbers = new char[5];
	int len_name_day = 3, len_name_month = 3;


	if(remaining_len < 3) // 3 это 2 цифры + обязательный пробел
			return 0;

	if(ProcessingTwoNumber(buffer[current_pos], buffer[current_pos+1], numbers, 31) == 0){
		delete [] numbers;
		return 0;
	}
	if(buffer[current_pos+2] != ' ' && buffer[current_pos+2] != 9){
		delete [] numbers;
		return 0;
	}
	remaining_len -=3;


	if(SearchNextNonWhitespaceChar(buffer, len, current_pos + len_name_day, current_pos, remaining_len) == 0){
		delete [] numbers;
		return 0;
	}

	if(remaining_len < 4){ // 4 это имя месяца + обязательный пробел
		delete [] numbers;
		return 0;
	}
	if(Month(buffer + current_pos) == false){
		delete [] numbers;
		return 0;
	}
	if(buffer[current_pos+len_name_month] != ' ' && buffer[current_pos+len_name_month] != 9){
		delete [] numbers;
		return 0;
	}
	remaining_len -= len_name_day + 1;

	
	if(SearchNextNonWhitespaceChar(buffer, len, current_pos + len_name_month+1, current_pos, remaining_len) == 0){
		delete [] numbers;
		return 0;
	}
	if(remaining_len < 5){ // 5 это 4 цифры в году xxxx + пробел
		delete [] numbers;
		return 0;
	}
	if(ProcessingFourNumber(buffer[current_pos],buffer[current_pos+1],buffer[current_pos+2],buffer[current_pos+3], 
				numbers, &CorrectYear) == 0){
		delete [] numbers;
		return 0;
	}
	if(buffer[current_pos+4] != ' ' && buffer[current_pos+4] != 9){
		delete [] numbers;
		return 0;
	}

	delete [] numbers;

	remaining_len -=5;
	current_pos +=5;
	
	return 1;
}

bool DayOfWeek(const char *buffer)
{
	if(strncmp(buffer, "Mon", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Tue", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Wed", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Thu", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Fri", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Sat", 3) == 0)
		return 1;	
	else if(strncmp(buffer, "Sun", 3) == 0)
		return 1;	
	return 0;
}

bool ProcessingDayOfWeek(const char *buffer, int len, int start_day_of_week, int &current_pos, int &remaining_len)
{
	int len_name_day = 3, next_symbol = 1;

	if(remaining_len < 4)
		return 0;
	if(DayOfWeek(buffer + start_day_of_week) == 0)
		return 0;
	if(buffer[start_day_of_week + len_name_day] != ',')
		return 0;
	remaining_len -= 4;

	if(SearchNextNonWhitespaceChar(buffer, len, start_day_of_week+len_name_day+next_symbol, current_pos, remaining_len) == 0)
		return 0;

	return 1;
}


int CheckDayOfWeek(const char *buffer, int len, int &start_day_of_week, int &start_date, int &remaining_len)
{
	int start_word = -1;
	
	//определение есть day_of_week или нет
	for(int i = 0; i < len; i++){
		if(buffer[i] == ','){
			if(start_word == -1)
				return -1;
			start_day_of_week = start_word;
			return 1;
		}	
		if(buffer[i] != ' ' && buffer[i] != 9 && start_word == -1){
			start_word = i;
			remaining_len -= start_word;
		}
	}
	
	//прошли всю строку и не нашли ',' - значит нет day of week
	
	//нет символов в строке
	if(start_word == -1)
		return -1;
	//есть символы
	start_date = start_word;

	return 0;
}



bool DateTime(char *buffer, int len)
{
	int start_day_of_week = -1, current_pos = 0, CRLF = 2;
	int remaining_len = len - CRLF;
	
	len = len - CRLF;

	
	if(CheckDayOfWeek(buffer, len, start_day_of_week, current_pos, remaining_len) == -1)
		return 0;
	
	//обработка day of week
	if(start_day_of_week > -1){
		if(ProcessingDayOfWeek(buffer, len, start_day_of_week, current_pos, remaining_len) == 0)
			return 0;
	}

	//обработка число месяц год	
	if(ProcessingDayMonthYear(buffer, len, current_pos, remaining_len) == 0)
		return 0;

	if(TimeOfDay(buffer, len, current_pos, remaining_len) == 0)
		return 0;

	//проверить на следуюзие символы. Не должно быть ничего кроме пробелов и CRLF
	for(int i=current_pos;i < len; i++){
		if(buffer[i] != ' ' && buffer[i] != 9)
			return 0;
	}


	return 1;
}

char *SeparateUnfoldingHeader(const char *buffer, int& len)
{
	char *tmp_buffer = new char[len];
	const char *CRLF = "\r\n";
	int pos_in_CRLF = 0, len_CRLF = 2;
	bool no_word = true;
	char ch;
	int j=0;


	for(int i = 0; i < len; i++){
		ch = buffer[i];
		if(ch == CRLF[pos_in_CRLF]){
			pos_in_CRLF++;
			continue;
		}
		if(pos_in_CRLF == len_CRLF){
			if(no_word){
				delete [] tmp_buffer;
				return 0;
			}
			no_word = true;
			tmp_buffer[j] = ' ';
			j++;
			pos_in_CRLF = 0;
			continue;
		}
		if(ch == '\n' || pos_in_CRLF != 0){
			delete [] tmp_buffer;
			return NULL;
		}
		
		if((ch > 32 && ch < 127) || ch == 32 || ch == 9){
			no_word = false;
			tmp_buffer[j] = ch;
			j++;
			continue;
		}

		delete [] tmp_buffer;
		return NULL;
	}
	tmp_buffer[j] = '\r'; tmp_buffer[j+1] = '\n';
	len = j+2;
	return tmp_buffer;
}



bool ParsingMsgId(const char *buffer, int& len, struct HeaderValueInfo &addresses)
{
	bool first_char_msg_id_received = false;
	bool need_space_chars = false;

	for(int i = 0; buffer[i] != '\r'; i++){
		if(addresses.address_count == addresses.address_max_size){
			AddSizeHeaderValueInfo(addresses);
		}
		
			
		if(buffer[i] != ' ' && buffer[i] != 9 && !first_char_msg_id_received){
			if(buffer[i] != '<'){
				delete [] buffer;
				return false;
			}
			first_char_msg_id_received = true;
			addresses.kinds[addresses.address_count] = NAME_ADDR;
			addresses.start_pos[addresses.address_count] = i;
			addresses.address_count++;
			continue;
		}
		if(buffer[i] == '>'){
			if(!first_char_msg_id_received){
				delete [] buffer;
				return false;
			}
			first_char_msg_id_received = false;
			//need_space_chars = true;
		}
	}

	if(first_char_msg_id_received){
		delete [] buffer;
		return false;
	}

	return true;
}

int ProcessingLocalAndDomainPartAddress(char *buffer, int start_position)
{
	int domain_part_start_position = 0,domain_part_lenght = 0,local_part_lenght = 0;
	int at = 1; //@

	if(AnalyzeLocalPartForFields(buffer, start_position, domain_part_start_position, local_part_lenght) == 0){
		return 0;
	}
	if(AnalyzeDomainPartForFields(buffer, domain_part_start_position, domain_part_lenght) == 0){

		return 0;
	}
	if(local_part_lenght + at + domain_part_lenght > MAX_LEN_DOMAIN){ 
		return 0;	
	}
	
	printf("count %d\n",local_part_lenght + at + domain_part_lenght);
	return local_part_lenght + at + domain_part_lenght;
}


bool FieldFrom(char *buffer, int len_buffer, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1; //для пропуска первой <
	int len_address = 0;
		    
	for(int i=0;i < addresses.address_count; i++){
		if(addresses.kinds[i] == GROUP)
			return 0;
		if(addresses.kinds[i] == NAME_ADDR){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i] + skip_opening_bracket);
			if(len_address == 0)
				return 0;
			puts("ok name addr");
			obj.AddFrom(buffer+addresses.start_pos[i] + skip_opening_bracket, len_address);

		}
		else if(addresses.kinds[i] == ADDR_SPEC){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i]);
			if(len_address == 0)
				return 0;
			puts("ok addr spec");
			obj.AddFrom(buffer+addresses.start_pos[i], len_address);
		}
	}
	obj.PrintFrom();
	return 1;
}



bool FieldSender(char *buffer, int len_buffer, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1;
	int len_address = 0;
	
	if(addresses.address_count > 1)
		return 0;

	if(addresses.kinds[0] == GROUP)
		return 0;
	if(addresses.kinds[0] == NAME_ADDR){
		len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0] + skip_opening_bracket);
		if(len_address == 0)
			return 0;
		puts("ok name addr");
		if(obj.AddSender(buffer+addresses.start_pos[0] + skip_opening_bracket, len_address) == 0)
			return 0;
	}
	else if(addresses.kinds[0] == ADDR_SPEC){
		len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0]);
		if(len_address == 0)
			return 0;
		puts("ok addr spec");
		if(obj.AddSender(buffer+addresses.start_pos[0], len_address) == 0)
			return 0;
	}
	obj.PrintSender();
	return 1;
}

bool FieldReplyTo(char *buffer, int len_buffer, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1;
	int len_address = 0;
		    
	for(int i=0;i<addresses.address_count;i++){
		if(addresses.kinds[i] == NAME_ADDR){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0] + skip_opening_bracket);
			if(len_address == 0)
				return 0;
			puts("ok name addr");
			if(obj.AddReplyTo(buffer+addresses.start_pos[0] + skip_opening_bracket, len_address) == 0)
				return 0;

		}
		else if(addresses.kinds[i] == ADDR_SPEC){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0] + skip_opening_bracket);
			if(len_address == 0)
				return 0;
			puts("ok addr spec");
			if(obj.AddReplyTo(buffer+addresses.start_pos[0] + skip_opening_bracket, len_address) == 0)
				return 0;
		}
	}

	obj.PrintReplyTo();

	return 1;
}




bool FieldToCcBcc(char *buffer, int len_buffer, struct HeaderValueInfo &addresses, ProcessingHeadersToRFC5322 &obj1,
								bool (ProcessingHeadersToRFC5322::*AddAddress)(char*, int))
{
	int skip_opening_bracket = 1;	
	int len_address = 0;
	
	for(int i=0;i<addresses.address_count;i++){
		if(addresses.kinds[i] == NAME_ADDR){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i] + skip_opening_bracket);
			if(len_address == 0)
				return 0;
			puts("ok name addr");
			(obj1.*AddAddress)(buffer+addresses.start_pos[i] + skip_opening_bracket, len_address);
		}
		else if(addresses.kinds[i] == ADDR_SPEC){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i]);
			if(len_address == 0)
				return 0;
			puts("ok addr spec");
			//AddAddress(buffer+addresses.start_pos[i], len_address);
		}
	}
	
	return 1;
}



bool MessageID(char *buffer, int len, struct HeaderValueInfo &addresses)
{
	int i=0, skip_opening_bracket = 1;
	int len_address = 0;

	if(addresses.address_count > 1)
		return 0;
	if(addresses.kinds[i] == NAME_ADDR){
		if(buffer[addresses.start_pos[i] + skip_opening_bracket] == '"')
			return 0;
		len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0] + skip_opening_bracket);
		if(len_address == 0)
			return 0;
		if(obj.AddMessageID(buffer+addresses.start_pos[0] + skip_opening_bracket, len_address) == 0)
			return 0;

		puts("ok name addr");
		}
	else return 0;

	obj.PrintMessageID();
	return 1;
}


bool InReplyTo(char *buffer, int len, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1;
	int len_address = 0;

	for(int i=0;i<addresses.address_count;i++){
		if(addresses.kinds[i] == NAME_ADDR){
			if(buffer[addresses.start_pos[i] + skip_opening_bracket] == '"')
				return 0;
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0] + skip_opening_bracket);
			if(len_address == 0)
				return 0;
			if(obj.AddInReplyTo(buffer+addresses.start_pos[0] + skip_opening_bracket, len_address) == 0)
				return 0;

			puts("ok name addr");
		}
		else return 0;
	}

	obj.PrintInReplyTo();
	return 1;
}

bool References(char *buffer, int len, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1;
	int len_address = 0;

	for(int i=0;i<addresses.address_count;i++){
		if(addresses.kinds[i] == NAME_ADDR){
			if(buffer[addresses.start_pos[i] + skip_opening_bracket] == '"')
				return 0;
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0] + skip_opening_bracket);
			if(len_address == 0)
				return 0;
			if(obj.AddReferences(buffer+addresses.start_pos[0] + skip_opening_bracket, len_address) == 0)
				return 0;

			puts("ok name addr");
		}
		else return 0;
	}

	obj.PrintReferences();
	return 1;
}


/*
bool FieldResentFrom(char *tmp_buffer, int len_buffer, struct HeaderValueInfo &addresses)
{
	int domain_part_start_position = 0,domain_part_lenght = 0,local_part_lenght = 0;
	int skip_opening_bracket = 1;
	int at = 1; //@
		
	for(int i=0;i<addresses.address_count;i++){
		if(addresses.kinds[i] == GROUP)
			return 0;
		if(addresses.kinds[i] == NAME_ADDR){
			if(AnalyzeLocalPartForFields(tmp_buffer,addresses.start_pos[i] + skip_opening_bracket,
						domain_part_start_position, local_part_lenght) == 0){
				return 0;
			}
			if(AnalyzeDomainPartForFields(tmp_buffer,domain_part_start_position, 
								domain_part_lenght, &isNameAddrEnd) == 0){
				return 0;
			}
			puts("ok name addr");

		}
		else if(addresses.kinds[i] == ADDR_SPEC){
			if(AnalyzeLocalPartForFields(tmp_buffer,addresses.start_pos[i], 
						domain_part_start_position, local_part_lenght) == 0){
				return 0;
			}
			if(AnalyzeDomainPartForFields(tmp_buffer,domain_part_start_position, 
								domain_part_lenght, &isAddrSpecEnd) == 0){
				return 0;
			}
			puts("ok addr spec");
		}
			
		if(local_part_lenght + at + domain_part_lenght > MAX_LEN_DOMAIN){ 
			return 0;	
		}
	}

	return 1;
}

bool FieldResentSender(char *tmp_buffer, int len_buffer, struct HeaderValueInfo &addresses)
{
	int domain_part_start_position = 0,domain_part_lenght = 0,local_part_lenght = 0;
	int skip_opening_bracket = 1;
	int at = 1; //@	

	if(addresses.address_count > 1)
		return 0;
	for(int i=0;i<addresses.address_count;i++){
		if(addresses.kinds[i] == GROUP)
			return 0;
		if(addresses.kinds[i] == NAME_ADDR){
			if(AnalyzeLocalPartForFields(tmp_buffer,addresses.start_pos[i] + skip_opening_bracket,
						domain_part_start_position, local_part_lenght) == 0){
				return 0;
			}
			if(AnalyzeDomainPartForFields(tmp_buffer,domain_part_start_position, 
								domain_part_lenght, &isNameAddrEnd) == 0){
				return 0;
			}
			puts("ok name addr");

		}
		else if(addresses.kinds[i] == ADDR_SPEC){
			if(AnalyzeLocalPartForFields(tmp_buffer,addresses.start_pos[i], 
						domain_part_start_position, local_part_lenght) == 0){
				return 0;
			}
			if(AnalyzeDomainPartForFields(tmp_buffer,domain_part_start_position, 
								domain_part_lenght, &isAddrSpecEnd) == 0){
				return 0;
			}
			puts("ok addr spec");
		}
		if(local_part_lenght + at + domain_part_lenght > MAX_LEN_DOMAIN){ 
			return 0;	
		}

	}

	return 1;
}
*/

bool AnalizeHeader(char *buffer, int read_count)
{
	int header_value_start= -1, header_field_end = -1;
	bool result = false;
	char *unfolding_header_value = NULL;
	HeaderValueInfo addresses;
	
	// разделяем поле и значение заголовка
	header_field_end = MyStrchr(buffer, ':', read_count);
	header_value_start = header_field_end + 1;	
	if(header_field_end == -1)
		return 0;
	buffer[header_field_end] = '\0';

	//приводим к одному регистру
	
	read_count = read_count - header_value_start; //исключаем длину поля заголовка

	//обрабатываем поля даты
	if((strcmp(buffer,"orig-date") == 0) || (strcmp(buffer,"resent-date") == 0) || (strcmp(buffer,"message-id") == 0)
		|| strcmp(buffer, "in-reply-to") == 0 || strcmp(buffer, "references") == 0){
		unfolding_header_value = SeparateUnfoldingHeader(buffer + header_value_start, read_count);
	}
	//обработка других типов заголовков(адреса)
	else{
		unfolding_header_value = ParseAddressHeaderField(buffer + header_value_start, read_count, addresses);
	}
	
	if(unfolding_header_value == NULL){
		return 0;
	}


	if(strcmp(buffer,"from") == 0){
		result = FieldFrom(unfolding_header_value, read_count, addresses);
		if(result == 0)
			return 0;
	}
	else if(strcmp(buffer,"sender") == 0){
		if(FieldSender(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}
	else if(strcmp(buffer,"reply-to") == 0){
		if(FieldReplyTo(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}
	
	else if(strcmp(buffer,"to") == 0){
		if(FieldToCcBcc(unfolding_header_value, read_count, addresses, obj, &ProcessingHeadersToRFC5322::AddTo) == 0)
			return 0;
		obj.PrintTo();
	}	
	else if(strcmp(buffer,"cc") == 0){
		if(FieldToCcBcc(unfolding_header_value, read_count, addresses, obj, &ProcessingHeadersToRFC5322::AddCc) == 0)
			return 0;
		obj.PrintCc();
	}	
	else if(strcmp(buffer,"bcc") == 0){
		if(FieldToCcBcc(unfolding_header_value, read_count, addresses, obj, &ProcessingHeadersToRFC5322::AddBcc) == 0)
			return 0;
		obj.PrintBcc();
	}
	else if(strcmp(buffer,"message-id") == 0){
		if(ParsingMsgId(unfolding_header_value, read_count, addresses) == 0)
			return 0;
		if(MessageID(unfolding_header_value, read_count, addresses) == 0)
			return 0;

	}
	
	else if(strcmp(buffer,"in-reply-to") == 0){
		if(ParsingMsgId(unfolding_header_value, read_count, addresses) == 0)
			return 0;

		if(InReplyTo(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}
	
	else if(strcmp(buffer,"references") == 0){
		if(ParsingMsgId(unfolding_header_value, read_count, addresses) == 0)
			return 0;

		if(References(unfolding_header_value, read_count, addresses) == 0)
			return 0;

	   }
	   /*
	else if(strcmp(buffer,"resent-from") == 0){
		if(FieldResentFrom(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}else if(strcmp(buffer,"resent-from") == 0){
		if(FieldResentSender(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}
	else if(strcmp(buffer,"resent-to") == 0 || strcmp(buffer,"resent-cc") == 0 || strcmp(buffer,"resent-bcc") == 0){
		if(FieldToCcBcc(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}
	else if(strcmp(buffer,"reply-message-id") == 0){
		if(MessageID(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}*/
	else if(strcmp(buffer,"orig-date") == 0){
		if(DateTime(unfolding_header_value, read_count) == 0)
			return 0;
		obj.AddDate(unfolding_header_value, read_count);
		obj.PrintDate();	
	}
	else if(strcmp(buffer,"resent-date") == 0){
		if(DateTime(unfolding_header_value, read_count) == 0)
			return 0;	
		obj.AddResentDate(unfolding_header_value, read_count);
		obj.PrintResentDate();
	}
	else if((strcmp(buffer,"subject") == 0) || (strcmp(buffer,"comments") == 0) || (strcmp(buffer,"keywords") == 0)){
		if((unfolding_header_value = SeparateUnfoldingHeader(buffer + header_value_start, read_count)) == 0)
			return 0;
		if(strcmp(buffer,"subject") == 0) {
			obj.AddSubject(buffer + header_value_start, read_count); 
			obj.PrintSubject();
		}
		else if(strcmp(buffer,"comments") == 0) {
			obj.AddComments(buffer + header_value_start, read_count);
			obj.PrintComments();
		}
		else if(strcmp(buffer,"keywords") == 0)	{
			obj.AddKeywords(buffer + header_value_start, read_count);
			obj.PrintKeywords();
		}
	}


	/*if(result == false)
		delete [] unfolding_header_value;
		*/
	buffer[header_field_end] = ':';
	return 1;
}






int FindNextHeaderField(const char *buffer, int len, int start_index_header, int &end_index_header)
{
	bool CRLF_received = true;
	if(buffer[0] != '\r') //пояснение в Readme. Важно только для 1 ситуации, ситуации конца блока заголовков
		CRLF_received = false;

	for(int i = start_index_header; i < len; i++){

		if(CRLF_received){
			if(buffer[i] == '\r'){ // конец заголовков
				if(i == 0)//не было ни одного заголовка и сразу конец заголовков - это ошибка
					return -1;
				end_index_header = i - 1; //\r\n\r, последний символ(\n) не смотрим, очевидно там будет \n
				return 0; // закончился блок заголовков
			}
			//Сюда включаю и случай с CRLF.CRLF . Пусть такой случай тоже считается началом нового заголовка
			//в след функциях такой вариант будет отброшен, так как нет такого заголовка с точкой.
			if(buffer[i] != ' ' && buffer[i] != 9){//CRLFchar
				end_index_header = i - 1;
				return 1; // получили очередной заголовок
			}
			//если пробельные символы, то это фальцовка
			CRLF_received = false;
		}
		if(buffer[i] == '\n'){ // если есть \n, то 100% было до него \r. значит на \r отдельно не нужно проверять
			CRLF_received = true;
			continue;
		}
	}
	
	//не встретили <CRLF><CRLF>, т.е. не было конца блока заголовков
	return -1;	
}

char *data = new char[100];
int AddData(char *buffer, int len)
{
	static int max_size_data = 100;
	static int current_size_data = 0;
	
	if(len + current_size_data > max_size_data){
		char *tmp = new char[max_size_data+100];
		for(int i = 0; i<max_size_data;i++)
			tmp[i] = data[i];
		delete [] data;
		data = tmp;
		max_size_data = max_size_data + 100;
	}
	for(int i = 0;i < len; i++)
		data[i+current_size_data] = buffer[i];
	current_size_data += len;
	data[current_size_data] = '\0';


	//printf("--\n%s--\n", data);
	
	return current_size_data;
}


int FindEndOfMailData(char *buffer, int read_count)
{
	const char *line_end = "\r\n";
	int current_position_end_line = 0, end_line_length = 2;
	//bool new_line_received = transaction.GetCRLF_received(), dot_received = transaction.GetDot_received();
	static bool new_line_received = false, dot_received = false, CR_received = false;

	if(CR_received){
		current_position_end_line = 1;
		CR_received = false;
	}

	for(int i=0;i<read_count;i++){
		
		if(buffer[i] != '\r' && buffer[i] != '\n' && buffer[i] != 32 && buffer[i] != 9 &&
				(buffer[i] < 32 || buffer[i] > 127)){
			return -1;
		}	

		if(buffer[i] == '.' && new_line_received && !dot_received){//!dot_received чтобы не было CRLF..
			dot_received = true;
			//transaction.SetDot_received(true);
			continue;
		}

		if(buffer[i] == line_end[current_position_end_line]){
			//получили CRLF
			if(current_position_end_line == end_line_length-1){
				//<CRLF>.<CRLF> - конец данных для DATA
				if(new_line_received && dot_received){
					dot_received = new_line_received = false;
					//transaction.SetDot_received(false);
					//transaction.SetCRLF_received(false);
					//transaction.AddData(buffer, i);
					return AddData(buffer, read_count);
					
				}
				//получили первый CRLF в строке
				//transaction.SetCRLF_received(true);
				new_line_received = true;
				current_position_end_line = 0;
				CR_received = false;
			}
			//Получили первый символ из CRLF - CR(\r)
			else{
				current_position_end_line++;
				CR_received = true;
			}
			continue;
		}
		
		if(buffer[i] == '\n' || current_position_end_line != 0){
			new_line_received = dot_received = CR_received = false;
			return -1;
		}

		dot_received = new_line_received = false;
		//transaction.SetCRLF_received(false);
		//transaction.SetDot_received(false);

		
	}
	
	AddData(buffer, read_count);
	return 0;
}


int GetMessageForData()
{
	int read_count, result;

	char *buffer = new char[100];
	int size_buffer = 100;
	
		
	read_count = read(0, buffer, size_buffer);
	
	if(read_count == 0){ // соединение закрыто - удалить клиента
		printf("соединеие закрыто\n");
		//удалить клиента
		//Destroy();
		return 0;
	}

	int len_data = FindEndOfMailData(buffer, read_count);
	if(len_data == 0) return 0;
	if(len_data == -1) return -1;

	//all_data_is_read = 1;
	//there_is_data_to_send = 1;
	
	int start_index_header = 0, end_index_header = 0;
	do{
		result = FindNextHeaderField(data, len_data, start_index_header, end_index_header);
		if(result != -1){
			if(AnalizeHeader(data + start_index_header, end_index_header - start_index_header) == 0){
				return -1;
			}
		}
		start_index_header = end_index_header + 1; //1 след символ
	}while(result > 0); // при result == 1, продолжаем
			    
	return result;
}


int main()
{
	int res = 0;
	while(res == 0)
		res = GetMessageForData();
	printf("%d\n", res);
	return 1;
}

//To: Кому непосредственно адресовано письмо
//Cc: Кому предназначена копия письма как бы для простого информирования ( они видят получаетелей из To и Cc )
//Bcc: Скрытые получатели
//Вариантов обработки есть 3, но я буду использовать вариант, где заголовок bcc удаляется перед отправкой и адресаты в to и cc
//не видят, что кто то есть в bcc. А адресаты bcc так же не видят bcc заголовок, не видят других адресатов в bcc и 
//такие адресаты вообще не видят даже свой адрес не в to, cc. Им просто приходит сообщение
