#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <cstring>
#include <errno.h>

#include <cstdlib>

//#include "Parsing_RFC5322_Headers.h"
#include "ClassMailTransaction.h"
#include "HeaderValueInfo.h"
#include "HeaderValueParseWorkset.h"

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
	from = reply_to = NULL; 
	sender = NULL;
	unfolding_from = unfolding_sender = unfolding_reply_to = NULL;
	len_addresses_from  = len_addresses_reply_to = NULL;
	len_addresses_sender = 0;
	size_from = size_reply_to = 0;  
	current_count_from = current_count_reply_to = 0;

	in_reply_to = references= NULL;
	message_id = NULL;
	unfolding_message_id = unfolding_in_reply_to = unfolding_references = NULL;
	len_addresses_message_id = 0;
	len_addresses_in_reply_to = len_addresses_references = NULL;
	size_in_reply_to = size_references= 0;
	current_count_in_reply_to = current_count_references = 0;
	
	to = cc = bcc = NULL;
	unfolding_to = unfolding_cc = unfolding_bcc = NULL;
	len_addresses_to = len_addresses_cc = len_addresses_bcc = NULL;
	size_to = size_cc = size_bcc = 0;
	current_count_to = current_count_cc = current_count_bcc = 0;

	orig_date = NULL;
	len_date = 0;

	subject = comments = keywords = NULL;
	len_subject = len_comments = len_keywords = 0;

	resent_from = NULL;
	resent_sender = NULL;
	unfolding_resent_from = unfolding_resent_sender = NULL;
	len_addresses_resent_from = NULL;
	len_addresses_resent_sender = size_resent_from = current_count_resent_from = 0;

	resent_to = resent_cc = resent_bcc = NULL;
	unfolding_resent_to = unfolding_resent_cc = unfolding_resent_bcc = NULL;
	len_addresses_resent_to = len_addresses_resent_cc = len_addresses_resent_bcc = NULL;
	size_resent_to = size_resent_cc = size_resent_bcc = 0;
	current_count_resent_to = current_count_resent_cc = current_count_resent_bcc = 0;

	resent_message_id = NULL;
	unfolding_resent_message_id = NULL;
	len_addresses_resent_message_id = 0;

	resent_date = NULL;
	len_resent_date = 0;
}

bool ProcessingHeadersToRFC5322::AddFrom(const char *value_header, int start_address, int len)
{
	if(size_from == 0){
		unfolding_from = value_header;
		from = new const char*[5];
		len_addresses_from = new int[5];
		size_from = 5;
	}
	else if(size_from == current_count_from){
		const char **tmp = new const char*[size_from + 5];
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

	from[current_count_from] = value_header + start_address;
	len_addresses_from[current_count_from] = len;
	current_count_from++;

	return true;
}

bool ProcessingHeadersToRFC5322::AddSender(const char *value_header, int start_address, int len)
{
	if(sender == NULL){
		unfolding_sender = value_header;
	}
	else{ return false; }

	sender = value_header+ start_address;
	len_addresses_sender = len;

	return true;
}

bool ProcessingHeadersToRFC5322::AddReplyTo(const char *value_header, int start_address, int len)
{
	if(size_reply_to == 0){
		unfolding_reply_to = value_header;
		reply_to = new const char*[5];
		len_addresses_reply_to = new int[5];
		size_reply_to = 5;
	}
	else if(size_reply_to == current_count_reply_to){
		const char **tmp = new const char*[size_reply_to + 5];
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

	reply_to[current_count_reply_to] = value_header + start_address;
	len_addresses_reply_to[current_count_reply_to] = len;
	current_count_reply_to++;

	return true;
}



bool ProcessingHeadersToRFC5322::AddMessageID(const char *value_header, int start_address, int len)
{
	if(message_id == NULL){
		unfolding_message_id = value_header;
	}
	else{ return false; }

	message_id = value_header + start_address;
	len_addresses_message_id = len;

	return true;
}



bool ProcessingHeadersToRFC5322::AddInReplyTo(const char *value_header, int start_address, int len)
{
	if(size_in_reply_to == 0){
		unfolding_reply_to = value_header;
		in_reply_to = new const char*[5];
		len_addresses_in_reply_to = new int[5];
		size_in_reply_to = 5;
	}
	else if(size_in_reply_to == current_count_in_reply_to){
		const char **tmp = new const char*[size_in_reply_to + 5];
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

	in_reply_to[current_count_in_reply_to] = value_header + start_address;
	len_addresses_in_reply_to[current_count_in_reply_to] = len;
	current_count_in_reply_to++;

	return true;
}


bool ProcessingHeadersToRFC5322::AddReferences(const char *value_header, int start_address, int len)
{
	if(size_references == 0){
		unfolding_references = value_header;
		references = new const char*[5];
		len_addresses_references = new int[5];
		size_references = 5;
	}
	else if(size_references == current_count_references){
		const char **tmp = new const char*[size_references + 5];
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

	references[current_count_references] = value_header + start_address;
	len_addresses_references[current_count_references] = len;
	current_count_references++;

	return true;
}



bool ProcessingHeadersToRFC5322::AddDate(const char *address, int len)
{
	if(orig_date != NULL){ return false;}

	orig_date = address;
	len_date = len;
	return true;
}



bool ProcessingHeadersToRFC5322::AddTo(const char *value_header, int start_address, int len)
{
	if(size_to == 0){
		unfolding_to = value_header;
		to = new const char*[5];
		len_addresses_to = new int[5];
		size_to = 5;
	}
	else if(size_to == current_count_to){
		const char **tmp = new const char*[size_to + 5];
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

	to[current_count_to] = value_header + start_address;
	len_addresses_to[current_count_to] = len;
	current_count_to++;

	return true;
}



bool ProcessingHeadersToRFC5322::AddCc(const char *value_header, int start_address, int len)
{
	if(size_cc == 0){
		unfolding_cc = value_header;
		cc = new const char*[5];
		len_addresses_cc = new int[5];
		size_cc = 5;
	}
	else if(size_cc == current_count_cc){
		const char **tmp = new const char*[size_cc + 5];
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

	cc[current_count_cc] = value_header + start_address;
	len_addresses_cc[current_count_cc] = len;
	current_count_cc++;

	return true;
}



bool ProcessingHeadersToRFC5322::AddBcc(const char *value_header, int start_address, int len)
{
	if(size_bcc == 0){
		unfolding_bcc = value_header;
		bcc = new const char*[5];
		len_addresses_bcc = new int[5];
		size_bcc = 5;
	}
	else if(size_bcc == current_count_bcc){
		const char **tmp = new const char*[size_bcc + 5];
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

	bcc[current_count_bcc] = value_header + start_address;
	len_addresses_bcc[current_count_bcc] = len;
	current_count_bcc++;

	return true;
}

bool ProcessingHeadersToRFC5322::AddSubject(const char *address, int len)
{
	if(subject != NULL){ return false;}

	subject = address;
	len_subject = len;

	return true;
}

bool ProcessingHeadersToRFC5322::AddComments(const char *address, int len)
{
	if(comments != NULL){ return false; }

	comments = address;
	len_comments = len;

	return true;
}



bool ProcessingHeadersToRFC5322::AddKeywords(const char *address, int len)
{
	if(keywords != NULL){ return false; }

	keywords = address;
	len_keywords = len;

	return true;
}



bool ProcessingHeadersToRFC5322::AddResentFrom(const char *value_header, int start_address, int len)
{
	if(size_from == 0){
		unfolding_resent_from = value_header;
		resent_from = new const char*[5];
		len_addresses_resent_from = new int[5];
		size_resent_from = 5;
	}
	else if(size_resent_from == current_count_resent_from){
		const char **tmp = new const char*[size_resent_from + 5];
		int *tmp_len = new int[size_resent_from + 5];
		for(int i=0; i < size_resent_from; i++){
			tmp[i] = resent_from[i];
			tmp_len[i] = len_addresses_resent_from[i];
		}
		delete [] resent_from;
		delete [] len_addresses_resent_from;
		resent_from = tmp;
		len_addresses_resent_from = tmp_len;
		size_resent_from = size_resent_from + 5;
	}

	resent_from[current_count_resent_from] = value_header + start_address;
	len_addresses_resent_from[current_count_resent_from] = len;
	current_count_resent_from++;

	return true;
}



bool ProcessingHeadersToRFC5322::AddResentSender(const char *value_header, int start_address, int len)
{
	if(resent_sender == NULL){
		unfolding_resent_sender = value_header;
	}
	else{
		return false;
	}

	resent_sender = value_header+ start_address;
	len_addresses_resent_sender = len;

	return true;
}

bool ProcessingHeadersToRFC5322::AddResentDate(const char *address, int len)
{
	if(resent_date != NULL){ return false; }

	resent_date = address;
	len_resent_date = len;
	return true;
}


bool ProcessingHeadersToRFC5322::AddResentTo(const char *value_header, int start_address, int len)
{
	if(size_resent_to == 0){
		unfolding_resent_to = value_header;
		resent_to = new const char*[5];
		len_addresses_resent_to = new int[5];
		size_resent_to = 5;
	}
	else if(size_resent_to == current_count_resent_to){
		const char **tmp = new const char*[size_resent_to + 5];
		int *tmp_len = new int[size_resent_to + 5];
		for(int i=0; i < size_resent_to; i++){
			tmp[i] = resent_to[i];
			tmp_len[i] = len_addresses_resent_to[i];
		}
		delete [] resent_to;
		delete [] len_addresses_resent_to;
		resent_to = tmp;
		len_addresses_resent_to = tmp_len;
		size_resent_to = size_resent_to + 5;
	}

	resent_to[current_count_resent_to] = value_header + start_address;
	len_addresses_resent_to[current_count_resent_to] = len;
	current_count_resent_to++;

	return true;
}



bool ProcessingHeadersToRFC5322::AddResentCc(const char *value_header, int start_address, int len)
{
	if(size_resent_cc == 0){
		unfolding_resent_cc = value_header;
		resent_cc = new const char*[5];
		len_addresses_resent_cc = new int[5];
		size_resent_cc = 5;
	}
	else if(size_resent_cc == current_count_resent_cc){
		const char **tmp = new const char*[size_resent_cc + 5];
		int *tmp_len = new int[size_resent_cc + 5];
		for(int i=0; i < size_resent_cc; i++){
			tmp[i] = resent_cc[i];
			tmp_len[i] = len_addresses_resent_cc[i];
		}
		delete [] resent_cc;
		delete [] len_addresses_resent_cc;
		resent_cc = tmp;
		len_addresses_resent_cc = tmp_len;
		size_resent_cc = size_resent_cc + 5;
	}

	resent_cc[current_count_resent_cc] = value_header + start_address;
	len_addresses_resent_cc[current_count_resent_cc] = len;
	current_count_resent_cc++;

	return true;
}



bool ProcessingHeadersToRFC5322::AddResentBcc(const char *value_header, int start_address, int len)
{
	if(size_resent_bcc == 0){
		unfolding_resent_bcc = value_header;
		resent_bcc = new const char*[5];
		len_addresses_resent_bcc = new int[5];
		size_resent_bcc = 5;
	}
	else if(size_resent_bcc == current_count_resent_bcc){
		const char **tmp = new const char*[size_resent_bcc + 5];
		int *tmp_len = new int[size_resent_bcc + 5];
		for(int i=0; i < size_resent_bcc; i++){
			tmp[i] = resent_bcc[i];
			tmp_len[i] = len_addresses_resent_bcc[i];
		}
		delete [] resent_bcc;
		delete [] len_addresses_resent_bcc;
		resent_bcc = tmp;
		len_addresses_resent_bcc = tmp_len;
		size_resent_bcc = size_resent_bcc + 5;
	}

	resent_bcc[current_count_resent_bcc] = value_header + start_address;
	len_addresses_resent_bcc[current_count_resent_bcc] = len;
	current_count_resent_bcc++;

	return true;
}



bool ProcessingHeadersToRFC5322::AddResentMessageID(const char *value_header, int start_address, int len)
{
	if(resent_message_id == NULL){
		unfolding_resent_message_id = value_header;
	}
	else{
		return false;
	}

	resent_message_id = value_header + start_address;
	len_addresses_resent_message_id = len;

	return true;
}

int MailTransaction::MyStrchr(char *buffer, char ch, int len)
{
	for(int i=0;i<len;i++){
		if(buffer[i] == ch)
			return i;
	}
	return -1;
}

bool MailTransaction::AllowQuotedPair(struct HeaderValueParseWorkset &ws)
{
	if(ws.atom || ws.name_addr) 
		return false;
	ws.quoted_pair = true;
	return true; 
}

bool MailTransaction::ProcessingComment(char ch, struct HeaderValueParseWorkset &ws)
{
	if(ws.quoted_string || ws.quoted_pair || ws.name_addr)
		return true;

	if(ch == '('){
		ws.open_comment_count++;
		ws.atom =  false;
		ws.comment = true;
	}
	else if(ch == ')'){
		ws.open_comment_count--;
		if(ws.open_comment_count < 0)	
			return false;
	}
	return true;
}

bool MailTransaction::ProcessingQuotedString(struct HeaderValueParseWorkset &ws)
{
	if(ws.quoted_pair || ws.comment || ws.name_addr)
		return true;
	if(ws.quoted_string == false){
		ws.atom = false;
		ws.has_opening_quote = ws.quoted_string = true;
	}
	else if(ws.quoted_string){
		ws.has_opening_quote = false;
	}
	
	return true;
}

bool MailTransaction::ProcessingAddress(char ch, struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses, 
														int index)
{
	if(ws.quoted_pair || ws.comment || ws.quoted_string)
		return true; //не обрабатываем

	if(ch == '<'){
		if(ws.name_addr || ws.was_name_addr)
			return false;
		ws.atom = false;
		ws.name_addr = true;
		addresses.start_pos[addresses.address_count] = index;
	}

	//проверка на > без <
	if(ch == '>' && !ws.name_addr)
		return false;
	return true;
}

bool MailTransaction::CheckCharAtom(char ch)
{
	//условия с (,),<,>,:,;,',', нельзя убрать, так как при использовании квотрирования эти символы будут допускаться
	//пример: hel(lo <mail@dom.ru>
	if(ch == '(' || ch == ')')
		return false;
	else if(ch == '<' || ch == '>')
		return false;
	else if( ch == '[' || ch == ']')
		return false;
	else if( ch == ':' || ch == ';')
		return false;
	else if( ch == '@' || ch == '\\')
		return false;
	else if(ch == ',' || ch == '.')
		return false;

	return true;
}


bool MailTransaction::CheckCorrectChar(char ch, struct HeaderValueParseWorkset &ws)
{
	if(ws.special_char){
		return true;
	}

	if((ch > 32 && ch < 127) || ch == 32 || ch == 9){
		if(ws.atom){
			if(CheckCharAtom(ch) == 0){
				ws.potentially_invalid_char = true;
				return true;
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
		return true;
	}
	return false;
}



bool MailTransaction::Group(struct HeaderValueParseWorkset &ws)
{
	if(ws.comment || ws.quoted_string || ws.quoted_pair /*|| ws.addr_spec*/ || ws.name_addr)
		return true;
	//состояние остается atom
	if(ws.group)
		return false;
	ws.special_char = ws.group = true;
	if(!ws.was_name_addr && !ws.was_comment && (ws.was_atom || ws.was_quoted_string)){
		ws.was_comment = ws.was_atom = ws.was_quoted_string = ws.was_name_addr = ws.mailbox_started = false;
		return true;
	}

	return false;
}


bool MailTransaction::CorrectAddrSpec(struct HeaderValueParseWorkset &ws)
{
	if(!ws.was_comment && (ws.was_atom || ws.was_quoted_string)){
		return true;
	}
	return false;
}
void MailTransaction::AddSizeHeaderValueInfo(struct HeaderValueInfo &addresses)
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

bool MailTransaction::ClassifyAddress( struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses)
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


bool MailTransaction::ProcessingComma(struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses)
{
	if(ws.comment || ws.quoted_string || ws.name_addr || ws.quoted_pair)
		return true;
	if(ws.mailbox_started == false){
		return false;
	}
	ws.mailbox_started = false;
	
	if(ClassifyAddress(ws, addresses) == false){
		return false;
	}
	ws.potentially_invalid_char = ws.comma_required = false;
	ws.was_comment = ws.was_atom = ws.was_quoted_string = ws.was_name_addr = false;
	ws.special_char = true;

	return true;
}

bool MailTransaction::ProcessingClosingGroup(struct HeaderValueParseWorkset &ws)
{
	if(ws.comment || ws.quoted_string || ws.quoted_pair || ws.name_addr)
		return true;
	if(ws.mailbox_started == false || !ws.group)
		return false;

	ws.group = false;
	ws.special_char = true;
	return true;
}

void MailTransaction::SetState(char ch, struct HeaderValueParseWorkset &ws, struct HeaderValueInfo &addresses, int index)
{
	ws.has_non_whitespace = true;
	if(!ws.special_char && !ws.mailbox_started){	
		ws.mailbox_started = true;
		addresses.start_pos[addresses.address_count] = index;
	}
	if(ws.special_char){
		if(ch == ';')
			ws.comma_required = true;
	}
	ws.special_char = false;
}

bool MailTransaction::ProcessDelimiter(char current_char, struct HeaderValueParseWorkset &ws, 
										struct HeaderValueInfo &addresses, int index)
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
		if(ProcessingAddress(current_char, ws, addresses, index) == false){
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
bool MailTransaction::ParseAddressHeaderField(const char *header, struct HeaderValueInfo &addresses)
{
	char current_char;
	struct HeaderValueParseWorkset ws;

	for(int i = 0; header[i] != '\r'; i++){
		current_char = header[i];

		if(addresses.address_count == addresses.address_max_size){
			AddSizeHeaderValueInfo(addresses);
		}

		// квотрирование символа 
		if(current_char == '\\' && !ws.quoted_pair){ //!ws.quoted_pair чтобы квотрировать символ '\'
			if(AllowQuotedPair(ws)){
				continue;
			}
			return false;
		}
		
		if(ProcessDelimiter(current_char, ws, addresses, i) == 0){
			return false;
		}
		
		//проверка допустимых символов
		if(CheckCorrectChar(current_char,ws) == 0){
			return false;
		}

		//если при требовании получения запятой дошли до сюда, то запятой не было или она квотрирована
		if(ws.comma_required && current_char != ' ' && current_char != 9){
			return false;
		}
		
		if(current_char != ' ' && current_char != 9){
			SetState(current_char, ws, addresses, i);		
		}

		ws.quoted_pair = false;
		
	}
	
	if(ClassifyAddress(ws, addresses) == false){
		return false;
	}
	if(ws.open_comment_count || ws.quoted_pair || ws.quoted_string || ws.name_addr || !ws.mailbox_started || ws.group){
		return false;
	}
	return true;
}





bool MailTransaction::ValidLocalChars(const char *buffer, int pos)
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


bool MailTransaction::ProcessingQuotedStringForLocalPart(const char *buffer, int start_position, int &domain_part_start_position, 													int &local_part_lenght)
{
	bool quoted_string = false, closed_quoted_string = false, quoted_pair = false, str_received = false;
	for(int i = start_position; buffer[i] != '\r'; i++){
		if(buffer[i] == '@' && !quoted_string){
			if(!str_received)
				return false;
			local_part_lenght = i - start_position;
			if(local_part_lenght > MAX_LEN_LOCAL_PART_ADDR)
				return false;
			domain_part_start_position = start_position + local_part_lenght + 1;
			return true;
		}
		if(buffer[i] == '\\' && !quoted_pair){
			quoted_pair = true;
			continue;
		}
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

bool MailTransaction::AnalyzeLocalPartForFields(const char *buffer, int start_position, int &domain_part_start_position, 
													int &local_part_lenght)
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
			if(local_part_lenght > MAX_LEN_LOCAL_PART_ADDR)
				return 0;
			return 1;
		}
		if(ValidLocalChars(buffer,i)){
			local_part_lenght++;
			char_reseived = true;
			dot_received = false;
			continue;
		}
		break;
	}
	
	return 0;
}

bool MailTransaction::ValidDomainChars(const char *buffer, int pos)
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


bool MailTransaction::AnalyzeDomainLiteral(const char *buffer, int domain_name_start_position, int &domain_part_lenght)
{	
	int max_digits_per_octet = 3; //ограничивает кол-во цифр в одном октете xxx.xxx.xxx.xxx
	int max_dots_in_ip_addr = 3; // ограничивает кол-во октетов в ip-адресе
	int current_count_digits = 0, current_count_dots = 0, i = 0;
	bool first_digit_received = 0;
	char current_char;

	const char dot_symbol = 46;

	domain_part_lenght++;
	
	for(i=domain_name_start_position+1; buffer[i] != ']'; i++){
		current_char = buffer[i];
		
		if(current_char == '[' || ((current_char < 47 || current_char > 58) && current_char != dot_symbol))
			return false;

		if(current_char == dot_symbol){
			current_count_dots++;
			if(current_count_dots > max_dots_in_ip_addr || first_digit_received == 0)
				return false;
			domain_part_lenght++;
			current_count_digits = first_digit_received = 0;
			continue;
		}

		if(first_digit_received == 0)
			first_digit_received = 1;

		current_count_digits++;

		if(current_count_digits > max_digits_per_octet)
			return false;

		domain_part_lenght++;
	}
	
	if(current_count_dots != max_digits_per_octet || current_count_digits == 0) 
		return false;
	domain_part_lenght++;
	
	i++;
	SearchNextNonWhitespaceChar(buffer, i);
	if(buffer[i] != ',' && buffer[i] != ';' && buffer[i] != '\r' && buffer[i] != '>')
	       return false;
	if(buffer[i] == '>'){
		i++;	
		SearchNextNonWhitespaceChar(buffer, i);
	}

	if((buffer[i] != '\r') && (buffer[i] != ',') && (buffer[i] != ';'))
		return false;

	return true;
}


bool MailTransaction::AnalyzeDomainPartForFields(const char *buffer, int start_position, int &domain_part_lenght)
{
	int i, lable_lenght = 0;
	bool new_label_received = false, FQDN_detected = false, space_received = false;
	
	domain_part_lenght = 0;

	//Проверяем на форму адреса вида [x.x.x.x]
	if(buffer[start_position] == '['){
		if(AnalyzeDomainLiteral(buffer, start_position, domain_part_lenght) == 0)
			return false;
		return true;
	}
	
	for(i=start_position; buffer[i] != ',' && buffer[i] != ';' && buffer[i] != '\r' && buffer[i] != '>'; i++){	
		if(buffer[i] == ' ' || buffer[i] == 9){
				space_received = true; //рассчитываю что это пробелы после адреса и до ,;\r или >
				continue;
		}
		if(ValidDomainChars(buffer, i)){
			if(space_received){ //если после таких пробелов есть символы, то это ошибка
				return false;
			}
			lable_lenght++;
			if(lable_lenght >= MAX_LEN_LABLE_DOMAIN)
				return false;
			if(new_label_received  == false)
				new_label_received = true;
			continue;
		}
		if(buffer[i] == 45){// 45(-)
			if(new_label_received == false)
				return false;
			lable_lenght++;
			continue;
		}

		if(buffer[i] == '.'){
			if(new_label_received == false)
				return false;
			new_label_received = false;
			FQDN_detected = true; // т.е. получили первую корректную точку, а значит домен будет корректен
			domain_part_lenght += (lable_lenght + 1);
			lable_lenght = 0;
			continue;
		}
		return false;
	}

	if(new_label_received == false || FQDN_detected == false)
		return false;
	
	if(buffer[i] == '>'){
		i++;
		SearchNextNonWhitespaceChar(buffer, i);
		if((buffer[i] != '\r') && (buffer[i] != ',') && (buffer[i] != ';') && (buffer[i] != '<'))
			return false;
	}

	domain_part_lenght += lable_lenght;

	return true;
}


int MailTransaction::SearchNextNonWhitespaceChar(const char *buffer, int &start_pos)
{
	int count_space = 0;

	for(int i = start_pos; true; i++, count_space++){
		if(buffer[i] != ' ' && buffer[i] != 9){
			start_pos = i;
			break;
		}
	}
	return count_space;
}

bool MailTransaction::ProcessingTwoNumber(const char ch1, const char ch2, char *numbers, int limit)
{
	int number = 0;
	if((ch1 > 57 || ch1 < 48) || (ch2 > 57 || ch2 < 48))
		return false;
	numbers[0] = ch1;
	numbers[1] = ch2;
	numbers[2] = '\0';
	number = (int)strtol(numbers, NULL, 10);
	if(number > limit)
		return false;
	return true;
}

bool MailTransaction::ProcessingFourNumber(const char ch1,const char ch2,const char ch3,const char ch4, char *numbers, 
		bool (MailTransaction::*CheckNumb)(int))
{
	int number = 0;

	if((ch1 > 57 || ch1 < 48) || (ch2 > 57 || ch2 < 48) || (ch3 > 57 || ch3 < 48) || (ch4 > 57 || ch4 < 48))
		return false;
	numbers[0] = ch1;
	numbers[1] = ch2;
	numbers[2] = ch3;
	numbers[3] = ch4;
	numbers[4] = '\0';
	number = (int)strtol(numbers, NULL, 10);
	if((this->*CheckNumb)(number) == 0)
		return false;
	return true;
}

bool MailTransaction::CorrectYear(int numb)
{
	if(numb < 1900)
		return false;
	return true;
}

bool MailTransaction::TimeZone(int numb)
{
	if(numb > 2359)
		return false;
	return true;
}

bool MailTransaction::TimeOfDay(const char *buffer, int &current_pos, int &remaining_len)
{
	char *numbers = new char[5];

	remaining_len -= SearchNextNonWhitespaceChar(buffer, current_pos);

	if(remaining_len < 5)// чч:мм
			return false;

	if(ProcessingTwoNumber(buffer[current_pos], buffer[current_pos+1], numbers, 23) == 0){
		delete [] numbers;
		return false;
	}
	if(buffer[current_pos+2] != ':'){
		delete [] numbers;
		return false;
	}
	remaining_len -=3;
	current_pos +=3;

	if(ProcessingTwoNumber(buffer[current_pos], buffer[current_pos+1], numbers, 59) == 0){
		delete [] numbers;
		return false;
	}

	remaining_len -=2;
	current_pos +=2;

	if(buffer[current_pos] == ':'){
		current_pos+=1;	
		remaining_len -=1;

		if(remaining_len < 2)
			return false;
		if(ProcessingTwoNumber(buffer[current_pos], buffer[current_pos+1], numbers, 59) == 0){
			delete [] numbers;
			return false;
		}
		current_pos +=2;
		remaining_len -=2;
	}

	if(buffer[current_pos] != ' ' && buffer[current_pos] != 9){
		delete [] numbers;
		return false;
	}
	current_pos +=1;
	remaining_len -=1;

	remaining_len -= SearchNextNonWhitespaceChar(buffer, current_pos);

	if(buffer[current_pos] != '+' && buffer[current_pos] != '-')
	       return false;
	current_pos +=1;
	remaining_len -=1;

	if(remaining_len < 4)
			return false;
	if(ProcessingFourNumber(buffer[current_pos],buffer[current_pos+1],buffer[current_pos+2],buffer[current_pos+3], 
				numbers, &MailTransaction::TimeZone) == 0){
		delete [] numbers;
		return false;
	}
	delete [] numbers;
	
	remaining_len -=4;
	current_pos +=4;
	
	return true;
}

bool MailTransaction::Month(const char *buffer)
{
	if(strncmp(buffer, "Jan", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Feb", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Mar", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Apr", 3) == 0)
		return true;	
	else if(strncmp(buffer, "May", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Jun", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Jul", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Aug", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Sep", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Oct", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Nov", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Dec", 3) == 0)
		return true;	
	
	return false;
}


bool MailTransaction::ProcessingDayMonthYear(const char *buffer, int &current_pos, int &remaining_len)
{
	char *numbers = new char[5];
	int len_name_day = 3, len_name_month = 3;


	if(remaining_len < 3) // 3 это 2 цифры + обязательный пробел
			return false;

	if(ProcessingTwoNumber(buffer[current_pos], buffer[current_pos+1], numbers, 31) == 0){
		delete [] numbers;
		return false;
	}
	if(buffer[current_pos+2] != ' ' && buffer[current_pos+2] != 9){
		delete [] numbers;
		return false;
	}
	remaining_len -=3;
	current_pos = current_pos + len_name_day;

	remaining_len -= SearchNextNonWhitespaceChar(buffer, current_pos);

	if(remaining_len < 4){ // 4 это имя месяца + обязательный пробел
		delete [] numbers;
		return false;
	}
	if(Month(buffer + current_pos) == false){
		delete [] numbers;
		return false;
	}
	if(buffer[current_pos+len_name_month] != ' ' && buffer[current_pos+len_name_month] != 9){
		delete [] numbers;
		return false;
	}
	remaining_len -= len_name_day + 1;
	current_pos = current_pos + len_name_month+1;
	
	remaining_len -= SearchNextNonWhitespaceChar(buffer, current_pos);
	
	if(remaining_len < 5){ // 5 это 4 цифры в году xxxx + пробел
		delete [] numbers;
		return false;
	}
	if(ProcessingFourNumber(buffer[current_pos],buffer[current_pos+1],buffer[current_pos+2],buffer[current_pos+3], 
				numbers, &MailTransaction::CorrectYear) == 0){
		delete [] numbers;
		return false;
	}
	if(buffer[current_pos+4] != ' ' && buffer[current_pos+4] != 9){
		delete [] numbers;
		return false;
	}

	delete [] numbers;

	remaining_len -=5;
	current_pos +=5;
	
	return true;
}

bool MailTransaction::DayOfWeek(const char *buffer)
{
	if(strncmp(buffer, "Mon", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Tue", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Wed", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Thu", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Fri", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Sat", 3) == 0)
		return true;	
	else if(strncmp(buffer, "Sun", 3) == 0)
		return true;	
	return false;
}

bool MailTransaction::ProcessingDayOfWeek(const char *buffer, int start_day_of_week, int &current_pos, int &remaining_len)
{
	int len_name_day = 3, next_symbol = 1;

	if(remaining_len < 4)
		return false;
	if(DayOfWeek(buffer + start_day_of_week) == 0)
		return false;
	if(buffer[start_day_of_week + len_name_day] != ',')
		return false;
	remaining_len -= 4;
	current_pos = start_day_of_week+len_name_day+next_symbol;

	remaining_len -= SearchNextNonWhitespaceChar(buffer, current_pos);

	return true;
}


int MailTransaction::CheckDayOfWeek(const char *buffer, int &start_day_of_week, int &start_date, int &remaining_len)
{
	int start_word = -1;
	
	//определение есть day_of_week или нет
	for(int i = 0; buffer[i] != '\r'; i++){
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



bool MailTransaction::DateTime(const char *buffer, int len, ProcessingHeadersToRFC5322 &header,
							bool (ProcessingHeadersToRFC5322::*AddAddress)(const char*, int))
{
	int start_day_of_week = -1, current_pos = 0, CRLF = 2;
	int remaining_len = len - CRLF;
	
	len = len - CRLF;

	if(CheckDayOfWeek(buffer, start_day_of_week, current_pos, remaining_len) == -1)
		return false;

	//обработка day of week
	if(start_day_of_week > -1){
		if(ProcessingDayOfWeek(buffer, start_day_of_week, current_pos, remaining_len) == 0)
			return false;
	}

	//обработка число месяц год	
	if(ProcessingDayMonthYear(buffer, current_pos, remaining_len) == 0)
		return false;

	if(TimeOfDay(buffer, current_pos, remaining_len) == 0)
		return false;

	//проверить на следующие символы. Не должно быть ничего кроме пробелов и CRLF
	/*for(int i=current_pos;i < len; i++){
		if(buffer[i] != ' ' && buffer[i] != 9)
			return false;
	}*/
	SearchNextNonWhitespaceChar(buffer, current_pos);
	if(buffer[current_pos] != '\r')
		return false;

	(header.*AddAddress)(buffer, len);
	return true;
}

bool MailTransaction::SeparateUnfoldingHeader(const char *header_line, char *unfolding_str, int& len_unfolding_str)
{
	const char *CRLF = "\r\n";
	int pos_in_CRLF = 0, len_CRLF = 2, j=0;
	bool no_word = true;
	char ch;

	for(int i = 0; i < len_unfolding_str; i++){
		ch = header_line[i];
		if(ch == CRLF[pos_in_CRLF]){
			pos_in_CRLF++;
			continue;
		}
		if(pos_in_CRLF == len_CRLF){
			if(no_word){
				return false;
			}
			no_word = true;
			unfolding_str[j] = ' ';
			j++;
			pos_in_CRLF = 0;
			continue;
		}
		if(ch == '\n' || pos_in_CRLF != 0){
			return false;
		}
		
		if((ch > 32 && ch < 127) || ch == 32 || ch == 9){
			no_word = false;
			unfolding_str[j] = ch;
			j++;
			continue;
		}
		return false;
	}
	if(no_word){	return false; }
	unfolding_str[j] = '\r'; unfolding_str[j+1] = '\n'; unfolding_str[j+2] = '\0';
	len_unfolding_str = j + 2;
	return true;
}



bool MailTransaction::IdentificationFields(const char *buffer, struct HeaderValueInfo &addresses)
{
	bool first_char_msg_id_received = false;

	for(int i = 0; buffer[i] != '\r'; i++){
		if(addresses.address_count == addresses.address_max_size){
			AddSizeHeaderValueInfo(addresses);
		}

		if(buffer[i] == '\"' || buffer[i] == '[' || buffer[i] == ']')
				return false;
		
		if(buffer[i] != ' ' && buffer[i] != 9 && !first_char_msg_id_received){
			if(buffer[i] != '<'){
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
				return false;
			}
			first_char_msg_id_received = false;
		}
	}

	if(first_char_msg_id_received){
		return false;
	}

	return true;
}

int MailTransaction::ProcessingLocalAndDomainPartAddress(const char *buffer, int start_position)
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
	
	return local_part_lenght + at + domain_part_lenght;
}

bool MailTransaction::HeaderFrom(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1; //для пропуска первой <
	int len_address = 0;
		    
	for(int i=0;i < addresses.address_count; i++){
		if(addresses.kinds[i] == GROUP)
			return false;
		if(addresses.kinds[i] == NAME_ADDR){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i] + skip_opening_bracket);
			if(len_address == 0)
				return false;
			headers.AddFrom(buffer, addresses.start_pos[i] + skip_opening_bracket, len_address);
		}
		else if(addresses.kinds[i] == ADDR_SPEC){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i]);
			if(len_address == 0)
				return false;
			headers.AddFrom(buffer, addresses.start_pos[i], len_address);
		}
	}
	return true;
}


bool MailTransaction::HeaderSender(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1;
	int len_address = 0;
	
	if(addresses.address_count > 1)
		return false;

	if(addresses.kinds[0] == GROUP)
		return false;
	if(addresses.kinds[0] == NAME_ADDR){
		len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0] + skip_opening_bracket);
		if(len_address == 0)
			return false;
		if(headers.AddSender(buffer, addresses.start_pos[0] + skip_opening_bracket, len_address) == 0)
			return false;
	}
	else if(addresses.kinds[0] == ADDR_SPEC){
		len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0]);
		if(len_address == 0)
			return false;
		if(headers.AddSender(buffer, addresses.start_pos[0], len_address) == 0)
			return false;
	}
	return true;
}



bool MailTransaction::HeaderReplyTo(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1;
	int len_address = 0;
		    
	for(int i=0;i<addresses.address_count;i++){
		if(addresses.kinds[i] == NAME_ADDR){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i] + skip_opening_bracket);
			if(len_address == 0)
				return false;
			if(headers.AddReplyTo(buffer, addresses.start_pos[i] + skip_opening_bracket, len_address) == 0)
				return false;

		}
		else if(addresses.kinds[i] == ADDR_SPEC){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i]);
			if(len_address == 0)
				return false;
			if(headers.AddReplyTo(buffer, addresses.start_pos[i], len_address) == 0)
				return false;
		}
	}

	return true;
}


bool MailTransaction::HeaderToCcBcc(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses, 
		ProcessingHeadersToRFC5322 &header, bool (ProcessingHeadersToRFC5322::*AddAddress)(const char*, int, int))
{
	int skip_opening_bracket = 1;	
	int len_address = 0;
	
	for(int i=0;i<addresses.address_count;i++){
		if(addresses.kinds[i] == NAME_ADDR){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i] + skip_opening_bracket);
			if(len_address == 0)
				return false;
			(header.*AddAddress)(buffer, addresses.start_pos[i] + skip_opening_bracket, len_address);
		}
		else if(addresses.kinds[i] == ADDR_SPEC){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i]);
			if(len_address == 0)
				return false;
			(header.*AddAddress)(buffer, addresses.start_pos[i], len_address);
		}
	}
	
	return true;
}

bool MailTransaction::HeaderMessageID(const char *buffer, int len, struct HeaderValueInfo &addresses)
{
	int i=0, skip_opening_bracket = 1;
	int len_address = 0;

	if(addresses.address_count > 1)
		return false;
	if(addresses.kinds[i] == NAME_ADDR){
		if(buffer[addresses.start_pos[i] + skip_opening_bracket] == '"')
			return false;
		len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0] + skip_opening_bracket);
		if(len_address == 0)
			return false;
		if(headers.AddMessageID(buffer, addresses.start_pos[0] + skip_opening_bracket, len_address) == 0)
			return false;

		}
	else return false;

	return true;
}


bool MailTransaction::HeaderInReplyTo(const char *buffer, int len, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1;
	int len_address = 0;

	for(int i=0;i<addresses.address_count;i++){
		if(addresses.kinds[i] == NAME_ADDR){
			if(buffer[addresses.start_pos[i] + skip_opening_bracket] == '"')
				return false;
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i] + skip_opening_bracket);
			if(len_address == 0)
				return false;
			if(headers.AddInReplyTo(buffer, addresses.start_pos[i] + skip_opening_bracket, len_address) == 0)
				return false;

		}
		else return 0;
	}

	return 1;
}

bool MailTransaction::HeaderReferences(const char *buffer, int len, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1;
	int len_address = 0;

	for(int i=0;i<addresses.address_count;i++){
		if(addresses.kinds[i] == NAME_ADDR){
			if(buffer[addresses.start_pos[i] + skip_opening_bracket] == '"')
				return false;
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i] + skip_opening_bracket);
			if(len_address == 0)
				return false;
			if(headers.AddReferences(buffer, addresses.start_pos[i] + skip_opening_bracket, len_address) == 0)
				return false;

		}
		else return false;
	}
	return 1;
}


bool MailTransaction::HeaderResentFrom(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1; //для пропуска первой <
	int len_address = 0;
		    
	for(int i=0;i < addresses.address_count; i++){
		if(addresses.kinds[i] == GROUP)
			return false;
		if(addresses.kinds[i] == NAME_ADDR){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i] + skip_opening_bracket);
			if(len_address == 0)
				return false;
			headers.AddResentFrom(buffer, addresses.start_pos[i] + skip_opening_bracket, len_address);
		}
		else if(addresses.kinds[i] == ADDR_SPEC){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i]);
			if(len_address == 0)
				return false;
			headers.AddResentFrom(buffer, addresses.start_pos[i], len_address);
		}
	}
	return true;
}

bool MailTransaction::HeaderResentSender(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses)
{
	int skip_opening_bracket = 1;
	int len_address = 0;
	
	if(addresses.address_count > 1)
		return false;

	if(addresses.kinds[0] == GROUP)
		return false;
	if(addresses.kinds[0] == NAME_ADDR){
		len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0] + skip_opening_bracket);
		if(len_address == 0)
			return false;
		if(headers.AddResentSender(buffer, addresses.start_pos[0] + skip_opening_bracket, len_address) == 0)
			return false;
	}
	else if(addresses.kinds[0] == ADDR_SPEC){
		len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0]);
		if(len_address == 0)
			return false;
		if(headers.AddResentSender(buffer, addresses.start_pos[0], len_address) == 0)
			return false;
	}
	return true;
}

bool MailTransaction::HeaderResentToCcBcc(const char *buffer, int len_buffer, struct HeaderValueInfo &addresses, 
		ProcessingHeadersToRFC5322 &header, bool (ProcessingHeadersToRFC5322::*AddAddress)(const char*, int, int))
{
	int skip_opening_bracket = 1;	
	int len_address = 0;
	
	for(int i=0;i<addresses.address_count;i++){
		if(addresses.kinds[i] == NAME_ADDR){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i] + skip_opening_bracket);
			if(len_address == 0)
				return false;
			(header.*AddAddress)(buffer, addresses.start_pos[i] + skip_opening_bracket, len_address);
		}
		else if(addresses.kinds[i] == ADDR_SPEC){
			len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[i]);
			if(len_address == 0)
				return false;
			(header.*AddAddress)(buffer, addresses.start_pos[i], len_address);
		}
	}
	return true;
}

bool MailTransaction::HeaderResentMessageID(const char *buffer, int len, struct HeaderValueInfo &addresses)
{
	int i=0, skip_opening_bracket = 1;
	int len_address = 0;

	if(addresses.address_count > 1)
		return false;
	if(addresses.kinds[i] == NAME_ADDR){
		if(buffer[addresses.start_pos[i] + skip_opening_bracket] == '"')
			return false;
		len_address = ProcessingLocalAndDomainPartAddress(buffer, addresses.start_pos[0] + skip_opening_bracket);
		if(len_address == 0)
			return false;
		if(headers.AddResentMessageID(buffer, addresses.start_pos[0] + skip_opening_bracket, len_address) == 0)
			return false;

		}
	else return false;

	return true;
}

void MailTransaction::ConvertToUppercase(char *header_field)
{
	for(int i=0;header_field[i] != '\0'; i++){  
		if(header_field[i] > 96 && header_field[i] < 123)
			header_field[i] = header_field[i] - 32;
	}
}

bool MailTransaction::AnalizeHeader(int start_index, int read_count)
{
	int header_value_start= -1, header_field_end = -1;
	bool result = false;
	char *unfolding_header_value = NULL;
	HeaderValueInfo addresses;

	char *buffer = mail_data + start_index;
	
	// разделяем поле и значение заголовка
	header_field_end = MyStrchr(buffer, ':', read_count);
	header_value_start = header_field_end + 1;	
	if(header_field_end == -1)
		return 0;
	buffer[header_field_end] = '\0';
	
	ConvertToUppercase(buffer);
	
	read_count = read_count - header_value_start; //исключаем длину поля заголовка

	unfolding_header_value = new char[read_count+1]; // +1 это для '\0'
								      //
	result = SeparateUnfoldingHeader(buffer + header_value_start, unfolding_header_value, read_count);
	if(result == false){
		delete [] unfolding_header_value;
		return 0;
	}

	if(strcmp(buffer,"from") == 0){
		result = HeaderFrom(unfolding_header_value, read_count, addresses);
		if(result == 0)
			return 0;
	}
	else if(strcmp(buffer,"sender") == 0){
		if(HeaderSender(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}
	else if(strcmp(buffer,"reply-to") == 0){
		if(HeaderReplyTo(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}
	else if(strcmp(buffer,"to") == 0){
		if(HeaderToCcBcc(unfolding_header_value, read_count, addresses, headers, &ProcessingHeadersToRFC5322::AddTo) == 0)
			return 0;
	}	
	else if(strcmp(buffer,"cc") == 0){
		if(HeaderToCcBcc(unfolding_header_value, read_count, addresses, headers, &ProcessingHeadersToRFC5322::AddCc) == 0)
			return 0;
	}	
	else if(strcmp(buffer,"bcc") == 0){
		if(HeaderToCcBcc(unfolding_header_value, read_count, addresses, headers, 
					&ProcessingHeadersToRFC5322::AddBcc) == 0)
			return 0;
	}
	else if(strcmp(buffer,"message-id") == 0){
		if(IdentificationFields(unfolding_header_value, addresses) == false)
			return 0;
		if(HeaderMessageID(unfolding_header_value, read_count, addresses) == 0)
			return 0;

	}
	else if(strcmp(buffer,"in-reply-to") == 0){
		if(IdentificationFields(unfolding_header_value, addresses) == false)
			return 0;
		if(HeaderInReplyTo(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}
	else if(strcmp(buffer,"references") == 0){
		if(IdentificationFields(unfolding_header_value, addresses) == false)
			return 0;
		if(HeaderReferences(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	} 
	else if(strcmp(buffer,"resent-from") == 0){
		if(HeaderResentFrom(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}
	else if(strcmp(buffer,"resent-sender") == 0){
		if(HeaderResentSender(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}
	else if(strcmp(buffer,"resent-to") == 0){
		if(HeaderResentToCcBcc(unfolding_header_value, read_count, addresses, headers, 
					&ProcessingHeadersToRFC5322::AddResentTo) == 0)
			return 0;
	}	
	else if(strcmp(buffer,"resent-cc") == 0){
		if(HeaderResentToCcBcc(unfolding_header_value, read_count, addresses, headers, 
					&ProcessingHeadersToRFC5322::AddResentCc) == 0)
			return 0;
	}	
	else if(strcmp(buffer,"resent-bcc") == 0){
		if(HeaderResentToCcBcc(unfolding_header_value, read_count, addresses, headers, 
					&ProcessingHeadersToRFC5322::AddResentBcc) == 0)
			return 0;
	}
	else if(strcmp(buffer,"resent-message-id") == 0){
		if(IdentificationFields(unfolding_header_value, addresses) == 0)
			return 0;
		if(HeaderResentMessageID(unfolding_header_value, read_count, addresses) == 0)
			return 0;
	}
	else if(strcmp(buffer,"orig-date") == 0){
		if(DateTime(unfolding_header_value, read_count, headers, &ProcessingHeadersToRFC5322::AddDate) == 0)
			return 0;
		}
	else if(strcmp(buffer,"resent-date") == 0){
		if(DateTime(unfolding_header_value, read_count, headers, &ProcessingHeadersToRFC5322::AddDate) == 0)
			return 0;	
	}
	else if((strcmp(buffer,"subject") == 0) || (strcmp(buffer,"comments") == 0) || (strcmp(buffer,"keywords") == 0)){
		if((SeparateUnfoldingHeader(buffer + header_value_start, unfolding_header_value, read_count)) == true){
			if(strcmp(buffer,"subject") == 0) {
				headers.AddSubject(unfolding_header_value, read_count); 
			}
			else if(strcmp(buffer,"comments") == 0) {
				headers.AddComments(unfolding_header_value, read_count);
			}
			else if(strcmp(buffer,"keywords") == 0)	{
				headers.AddKeywords(unfolding_header_value, read_count);
			}
		}
	}


	/*if(result == false)
		delete [] unfolding_header_value;
		*/
	buffer[header_field_end] = ':';
	return 1;
}


int MailTransaction::FindNextHeaderField(int start_index_header, int &end_index_header)
{
	CRLF_received = true;
	if(mail_data[0] != '\r') //пояснение в Readme. Важно только для 1 ситуации, ситуации конца блока заголовков беззаголовков
		CRLF_received = false;

	for(int i = start_index_header; i < mail_data_size; i++){

		if(CRLF_received){
			if(mail_data[i] == '\r'){ // конец заголовков
				if(i == 0)//не было ни одного символа(а значит и заголовка) и сразу конец заголовков - это ошибка
				{ return -1; }
				end_index_header = i - 1; //\r\n\r, последний символ(\n) не смотрим, очевидно там будет \n
				return 0; // закончился блок заголовков
			}
			//Сюда включаю и случай с CRLF.CRLF . Пусть такой случай тоже считается началом нового заголовка
			//в след функциях такой вариант будет отброшен, так как нет такого заголовка с точкой.
			if(mail_data[i] != ' ' && mail_data[i] != 9){//CRLFchar
				end_index_header = i - 1;
				return 1; // получили очередной заголовок
			}
			//если пробельные символы, то это фальцовка
			CRLF_received = false;
		}
		if(mail_data[i] == '\n'){ // если есть \n, то 100% было до него \r. значит на \r отдельно не нужно проверять
			CRLF_received = true;
			continue;
		}
	}
	
	//не встретили <CRLF><CRLF>, т.е. не было конца блока заголовков
	return -1;	
}

int MailTransaction::AppendMailData(const char *new_data, int len_new_data)
{
	int null_terminator = 1;

	if(len_new_data + mail_data_size > mail_data_max_size - null_terminator){
		char *tmp = new char[mail_data_max_size+100];

		for(int i = 0; i<mail_data_max_size - null_terminator;i++)
			tmp[i] = mail_data[i];
		delete [] mail_data;

		mail_data = tmp;
		mail_data_max_size = mail_data_max_size + 100;
	}
	for(int i = 0;i < len_new_data; i++)
		mail_data[i+mail_data_size] = new_data[i];

	mail_data_size += len_new_data;
	mail_data[mail_data_size] = '\0';

	return mail_data_size;
}


int MailTransaction::FindEndOfMailData(const char *buffer, int read_count)
{
	const char *line_end = "\r\n";
	int current_position_end_line = 0, end_line_length = 2;

	if(CR_received){
		current_position_end_line = 1;
		CR_received = false;
	}

	for(int i=0;i<read_count;i++){
		
		if(buffer[i] != '\r' && buffer[i] != '\n' && buffer[i] != 32 && buffer[i] != 9 &&
				(buffer[i] < 32 || buffer[i] > 127)){
			return -1;
		}	

		if(buffer[i] == '.' && CRLF_received && !dot_received){//!dot_received чтобы не было CRLF..
			dot_received = true;
			continue;
		}

		if(buffer[i] == line_end[current_position_end_line]){
			//получили CRLF
			if(current_position_end_line == end_line_length-1){
				//<CRLF>.<CRLF> - коне
				//Гарантирует, что в строке будет хоть один символ помимо CRLFц данных для DATA
				if(CRLF_received && dot_received){
					dot_received = CRLF_received = false;
					return AppendMailData(buffer, read_count);
				}
				//получили первый CRLF в строке
				CRLF_received = true;
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
			CRLF_received = dot_received = CR_received = false;
			return -1;
		}

		dot_received = CRLF_received = false;
	}
	
	AppendMailData(buffer, read_count);
	return 0;
}


MailTransaction tr;
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

	int len_data = tr.FindEndOfMailData(buffer, read_count);
	if(len_data == 0) return 0;
	if(len_data == -1) return -1;

	//all_data_is_read = 1;
	//there_is_data_to_send = 1;
	
	int start_index_header = 0, end_index_header = 0;
	do{
		result = tr.FindNextHeaderField(start_index_header, end_index_header);
		if(result != -1){
			if(tr.AnalizeHeader(start_index_header, end_index_header - start_index_header + 1) == 0){
				return -1;
			}
		}
		start_index_header = end_index_header + 1; //1 след символ
	}while(result > 0); // при result == 1, продолжаем
			    
	return result;
}






/*
int main()
{
	int res = 0;
	while(res == 0)
		res = GetMessageForData();
	printf("%d\n", res);
	return 1;

}*/

//To: Кому непосредственно адресовано письмо
//Cc: Кому предназначена копия письма как бы для простого информирования ( они видят получаетелей из To и Cc )
//Bcc: Скрытые получатели
//Вариантов обработки есть 3, но я буду использовать вариант, где заголовок bcc удаляется перед отправкой и адресаты в to и cc
//не видят, что кто то есть в bcc. А адресаты bcc так же не видят bcc заголовок, не видят других адресатов в bcc и 
//такие адресаты вообще не видят даже свой адрес не в to, cc. Им просто приходит сообщение
