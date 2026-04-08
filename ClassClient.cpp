#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include <fcntl.h>

#include <cerrno>
#include <cstring>

#include "ClassClient.h"


#define MAX_NAME_CLIENT 100
#define MAX_COMMAND_LINE 512
#define MAX_LEN_LOCAL_PART_ADDR 64
#define MAX_LEN_LABLE_DOMAIN 63
#define MAX_LEN_DOMAIN 255

//Что на счет глобальных переменных? как должны выглядить
const char *error_command = "500 Syntax error, command unrecognized\r\n";
const char *error_arguments = "501 Syntax error in parameters or arguments\r\n";
const char *max_recipients_rcpt_to = "5xx Too many resipients\r\n"; // мременная
const char *cmd_line_too_long = "500 Command line too long\r\n";

const char *invalid_command = "503 Invalid command\r\n";
const char *too_long_line = "502 This line is very long\r\n";
const char *too_short_line = "502 This line is very short\r\n";


const char *welcome = "220 Welcome\n";
const char *smtp_greeting = "220 SMTP\r\n"; //переименовать					    //
const char * OK = "250 OK\n";
const char *waiting_data = "354 Start mail input\r\n";



///////имею static переменную если буду реализовывать многопоточку надо учитывать!ё

/*bool Client::AnalysysHeader(int end_header)
{
	const char* Data = "Data"; // временно здесь будут
	const char* Address = "Data"; // временно здесь будут
	size_arr_str = 2;
	char *arr_str[2] = {Data, Address};

	for(int i=0; i < size_arr_str; i++){
		if(strncmp(arr_str[i], buffer, end_header-1) != 0){
			return 1;
		}
	}

	return 0;
}*/

/*bool Client::FindHeaders()
{
	for(int i=0;i < size_buffer; i++){
		if(buffer[i] == ':'){
			break;
		}
		if(buffer[i] < 33 || buffer[i] > 126){
			return ?
		}
	}

	return AnalysysHeader(i);
}*/

bool Client::AnalisysGetData()
{

	return 0;
}



bool Client::AnalisysAnswer()
{
	int result;
	if(current_step == AwaitingGreeting){
		result = AnalyzeWelcome();
		buffer[0] = '\0';
	}
	else if(current_step == Mail){
		result = AnalisysMail();
		buffer[0] = '\0';
	}
	else if(current_step == RCPT){
		result = AnalisysRCPT();
		buffer[0] = '\0';
	}
	else if(current_step == Data){
		result = AnalisysData();
		buffer[0] = '\0';
	}	
	else if(current_step == GetData){
		result = AnalisysGetData();
		buffer[0] = '\0';
	}

	return result;
}

bool Client::HaveError()
{
	if(error != NULL)
		return 1;
	
	return 0;
}

void Client::NextStep(Step next_step) // функция с параметром по умолчанию. ???
{
	if(error == NULL) // если есть ошибка, значит при чтении полученный данных была ошибка, значит текущий шаг остается
		current_step = next_step;	
	buffer[0] = '\0';
	there_is_data_to_send = false;
	error = response = NULL;	
}

int Client::SendResponse()
{
	int write_count;
	const char *str;

	all_data_is_read = false; // отключает, после удачного GetMessage (или похожего)

	if(HaveError()){
		str = error;
	}
	else
		str = response;

	if(buffer[0] != '\0')
		write_count = write(socket, buffer, strlen(buffer));
	else 
		write_count = write(socket, str, strlen(str));
	
	if(write_count == -1){ //разорвал соедине клинет
		//Удалить клиента при любой ошибке связанная с сокетом 
		Destroy();
		return 0;
		////Решить с сигналом EINTR
	}
	if(write_count < (int)strlen(str)){
		strcpy(buffer, str+strlen(buffer)+write_count); // оставляем step=welcome
		//there_is_data_to_send = true;		
		return 0;
	}
	

	return 1;
}

/*const char* Client::IdentifyError(Error &error)
{
	switch(error){
		case ShortLine:	return too_short_line;
		case LongLine:	return too_long_line;
		case NoError: return "bla bla"; //чтобы не ругался компил 

	}

	return NULL; /// Что будет возвращать? ЧТобы не было предупреждения если удалю

}*/


int Client::AnalyzeMessageForData(int read_count)
{
	const char *line_end = "\r\n";
	int current_position_end_line = 0, end_line_length = 2;
	bool new_line_received = transaction.GetCRLF_received(), dot_received = transaction.GetDot_received();
	bool CR_received = transaction.GetCR_received();

	if(CR_received){
		current_position_end_line = 1;
		CR_received = false;
	}

	for(int i=0;i<read_count;i++){
		
		if(buffer[i] != '\r' && buffer[i] != '\n' && buffer[i] != 32 && buffer[i] != 9 &&
				(buffer[i] < 32 || buffer[i] > 127)){

			transaction.SetCR_received(false); transaction.SetCRLF_received(false); 
			transaction.SetDot_received(false);
			return -1;
		}	

		if(buffer[i] == '.' && new_line_received && !dot_received){//!dot_received чтобы не было CRLF..
			dot_received = true;
			continue;
		}

		if(buffer[i] == line_end[current_position_end_line]){
			//получили CRLF
			if(current_position_end_line == end_line_length-1){
				//<CRLF>.<CRLF> - конец данных для DATA
				if(new_line_received && dot_received){
					dot_received = new_line_received = false;
					transaction.SetCR_received(CR_received); 
					transaction.SetCRLF_received(new_line_received); 
					transaction.SetDot_received(dot_received);
					transaction.AddData(buffer, i);
					return 1;
				}
				//получили первый CRLF в строке
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
			//new_line_received = dot_received = CR_received = false;
			transaction.SetCR_received(false); transaction.SetCRLF_received(false); 
			transaction.SetDot_received(false);

			return -1;
		}

		dot_received = new_line_received = false;
		
	}
	
	transaction.SetCR_received(CR_received); 
	transaction.SetCRLF_received(new_line_received); 
	transaction.SetDot_received(dot_received);

	transaction.AddData(buffer, read_count);
	return 0;
}


/*bool Client::AnalyzeMessageForData(int read_count)
{
	const char *line_end = "\r\n";
	int current_position_end_line = 0, end_line_length = 2;
	static bool new_line_received = false, dot_received = false;
	int has_incomplete_CRLF = 0, skip_first_dot = 0;
	
	for(int i=0;i<read_count;i++){
		if(buffer[i] == '.' && (new_line_received || dot_received)){
			if(dot_received){
				skip_first_dot = 1;
				dot_received = new_line_received = false;
			}
			else if(new_line_received){	
				dot_received = true;
			}
			continue;
		}
		if(buffer[i] == line_end[current_position_end_line]){
			//получили CRLF
			if(current_position_end_line == end_line_length-1){
				//<CRLF>.<CRLF> - конец данных для DATA
				if(new_line_received && dot_received){
					dot_received = new_line_received = false;
					//transaction.AddData(buffer, i-3);
					return 1;
				}
				//<CRLF><CRLF> - конец блока заголовков
				if(new_line_received && transaction.GetHeaderBlockEndPosition() == -1){
					transaction.SetHeaderBlockEndIndex(i);
				}
				//получили первый CRLF в строке
				new_line_received = true;
				current_position_end_line = 0;
			}
			else
				current_position_end_line++;
			continue;
		}
		if(buffer[i] == '\n' || current_position_end_line != 0){
			return -1;
		}
		dot_received = new_line_received = false;
	}

	if(buffer[read_count-1] == '\r'){
		transaction.AddToBufferIncompleteCRLF("\r");
		has_incomplete_CRLF = 1;
	}
	else{
		transaction.AddToBufferIncompleteCRLF("");
	}
//vdfv<CRLF>vdf - след заголовок
	//vdfv<CRLF> vdf - фольцовка заголовка
	//vdf<CRLF><CRLF> - конец заголовков
	//vdf<CRLF>.<CRLF> - конец данных
	//vdf<CRLF>..<CRLF> - прозрачность

	transaction.AddData(buffer + skip_first_dot, read_count - has_incomplete_CRLF - skip_first_dot);
	return 0;
}*/

bool Client::GetMessageForData()
{
	int read_count, result;
	int chars_from_bufferCRLF = 0;
	
	/*if(transaction.IsDataInBufferCRLF()){
		buffer[0] = '\0';
		strcpy(buffer, transaction.GetBufferCRLF());
		chars_from_bufferCRLF = strlen(transaction.GetBufferCRLF());
	}*/
		
	//read_count = read(socket, buffer+chars_from_bufferCRLF, size_buffer10 - chars_from_bufferCRLF);
	read_count = read(socket, buffer, size_buffer);

	if(read_count == 0){ // соединение закрыто - удалить клиента
		printf("соединеие закрыто\n");
		//удалить клиента
		Destroy();
		return 0;
	}

	// ?????
	if((result = AnalyzeMessageForData(read_count+chars_from_bufferCRLF)) == 0){
		return 0;
	}
	
	result = AnalisysAnswer();
	//обработка все полученных данных. Поиск заголовков и конца блока заголовков
	
	all_data_is_read = 1;
	there_is_data_to_send = 1;				
	return 0;
	//return AnalisysAnswer();
}


bool Client::GetMessage()
{
	int read_count;
	int last_symbol = 1, penultimate_symbol = 2;


	all_data_is_read = false; //устанавливаем в начальное положение

	read_count = read(socket, buffer, size_buffer);
	if(read_count < 2){
		SetUnSuccessfulResponse(too_short_line);
		return 0; 	
	}
	if(read_count == 0){ // соединение закрыто - удалить клиента
		//удалить клиента
		Destroy();
		return 0;
	}
	if(buffer[read_count - penultimate_symbol] != '\r' 
		&& buffer[read_count-last_symbol] != '\n' )// не полная str
	{
		SetUnSuccessfulResponse(too_long_line);
		return 0;
	}

	if(read_count > MAX_COMMAND_LINE){
		SetUnSuccessfulResponse(cmd_line_too_long);
		return 0;
	}
	all_data_is_read = true;
	there_is_data_to_send = true;				
	return AnalisysAnswer();
}


// где используется?
int Client::SendError()
{
	//const char *str_error = IdentifyError(error);
	int write_count;

	if(buffer[0] != '\0')
		write_count = write(socket, buffer, strlen(buffer));
	else 
		write_count = write(socket, error, strlen(error));
		
	if(write_count == -1){ //разорвал соедине клинет
		//Удалить клиента при любой ошибке связанная с сокетом 
		Destroy();
		return 0;
		////Решить с сигналом EINTR
	}

	if(write_count < strlen(error)){
		strcpy(buffer, error+write_count); // оставляем step
		there_is_data_to_send = 1;
		return 0;		
	}
	all_data_is_read = 0;
	transaction.ResetAdditionalRecipient();

	return 1;
}

Client::Client(unsigned int sct)
{
	socket = sct;
	size_buffer = 1000;
	buffer = new char[size_buffer];
	buffer[0] = '\0';
	current_step = Welcome;
	error = NULL;	
	response = smtp_greeting;
	there_is_data_to_send = true;
	delete_client = false;
	all_data_is_read = false;
}

Client::~Client()
{
	close(socket);
	delete [] buffer;
}







//----------------------------------------------------------------------------------------------------------------------------
void Client::ConvertToUppercase()
{
	for(int i=0;buffer[i] != '\0'; i++){  
		if(buffer[i] > 96 && buffer[i] < 123)
			buffer[i] = buffer[i] - 32;
	}
}

bool Client::AnalyzeHELO(int &start_command, int &start_domain)
{
	int end_argument_index, current_pos;
	bool command_received = false;
	
	//получили первое слово
	for(int i=0; 1; i++){
		if(buffer[i] == '\r' || buffer[i] == 9) // так и не встретили пробельного символа (при получении \r)
			return 0;
		if(buffer[i] == ' '){
			if(command_received == false) // есть пробел, но командное слово не получили
				return 0;
			buffer[i] = '\0'; // получили командное слово
			current_pos = i+1; 
			break;
		}
		command_received = true; // Любой символ кроме пробельных
	}
	
	//ожидаем не пробельные символы, т.е. первый символ аргумента
	if(buffer[current_pos] == ' ' || buffer[current_pos] == 9 || buffer[current_pos] == '\r')
		return 0;
	current_pos++;

	//находим конец аргумента
	for(int i=current_pos; 1; i++){
		if(buffer[i] == ' ' || buffer[i] == 9 || buffer[i] == '\r'){
			end_argument_index = i;
			current_pos = end_argument_index+1;
			break;
		}
	}
	
	//если после аргумента есть символы, то это ошибка
	for(int i=current_pos; buffer[i] != '\r' && buffer[i] != '\n'; i++){
		if(buffer[i] != ' ' && buffer[i] != 9)
			return 0;
	}
	
	return 1;
}

bool Client::AnalyzeDomain(int &domain_name_start_position, int &domain_part_lenght, char end_str)
{	
	int max_digits_per_octet = 3; //ограничивает кол-во цифр в одном октете xxx.xxx.xxx.xxx
	int max_dots_in_ip_addr = 3; // ограничивает кол-во октетов в ip-адресе
	int current_count_digits = 0, current_count_dots = 0;
	bool first_digit_received = 0;
	char current_char;
	int i;

	const char dot_symbol = 46;


	if(buffer[domain_name_start_position] != '[') // Если здесь нет ip-адрес, то считаю что адрес корректный
			return 1;
	domain_part_lenght++;
	
	for(i = domain_name_start_position+1; 1; i++){
		current_char = buffer[i];
		
		if(buffer[i+1] == end_str){
			break;
		}

		if(current_char == '[' || current_char == ']' || 
				((current_char < 47 || current_char > 58) && current_char != dot_symbol))
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
	
	if(current_char != ']' || current_count_dots != max_digits_per_octet || current_count_digits == 0) 
		return 0;
	domain_part_lenght++;

	return 1;
}


bool Client::AnalyzeWelcome()
{
	int start_command = 0, start_domain = 0; // or address literal [xx.x.xx.x]
	int domain_part_lenght = 0; // переменная не нужна, но необхожимо создать чтобы функция отработала
			
	//отделяем команду от аргументов, команда получает последним символом '\0'
	if(AnalyzeHELO(start_command, start_domain) == 0){ 
		SetUnSuccessfulResponse(error_command);
		return 0;
	}

	ConvertToUppercase(); // Приводим команду к единому регистру

	if(strcmp(buffer, "HELO") == 0){
		if(AnalyzeDomain(start_domain, domain_part_lenght, '\0') == 0){
			SetUnSuccessfulResponse(error_arguments);
			return 0;
		}
		SetSuccessfulResponse(welcome);
		return 1;
	}
	else if(strcmp(buffer, "EHLO") == 0){
		// Реализовать
		SetSuccessfulResponse(welcome);
		return 1;
	}
	
	SetUnSuccessfulResponse(error_command);
	return 0;
}

int Client::MyStrchr(char *buffer, char chr) // пока она здесь, потом перенесу
{
	for(int i = 0; buffer[i] != '\r'; i++){
		if(buffer[i] == chr)
			return i;
	}
	return -1;
}
bool Client::AnalyzeMailFrom(int &argument_start_postition)
{
	int colomn_index, open_bracket_index, close_bracket_index, current_index;

	//находим конец команды
	colomn_index = MyStrchr(buffer, ':');
	if(colomn_index == -1)
		return 0;
	buffer[colomn_index] = '\0';
	current_index = colomn_index+1;

	//Находим начало аргумента
	open_bracket_index = MyStrchr(buffer+current_index, '<');
	if(open_bracket_index == -1)
		return 0;
	argument_start_postition = open_bracket_index += current_index;
	current_index = open_bracket_index+1;

	//находим конец аргумента
	close_bracket_index = MyStrchr(buffer+current_index, '>');
	if(close_bracket_index == -1)
		return 0;
	close_bracket_index += current_index;

	//проверяем правильный порядок <>
	if(open_bracket_index > close_bracket_index)
		return 0;
	current_index = close_bracket_index+1;
						
	//проверяем что после аргумента больше нет символов	
	for(int i=current_index; buffer[i] != '\r'; i++){
		if(buffer[i] != ' ' && buffer[i] != 9)
			return 0;
	}
	
	return 1;
}

bool Client::ValidDomainChars(int pos)
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

bool Client::AnalyzeDomainPart(int &start_position, int &domain_part_lenght)
{
	int i, lable_lenght = 0, count_closing_angle_bracket = 0;
	bool new_label_received = false, FQDN_detected = false;
	
	//Проверяем на форму адреса вида [x.x.x.x]
	if(buffer[start_position] == '['){
		if(AnalyzeDomain(start_position, domain_part_lenght, '>') == 0)
			return 0;
		return 1;
	}
	
	//протестировать этот кусок
	for(i=start_position; buffer[i] != '\r'; i++){	
		if(ValidDomainChars(i)){
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

		if(buffer[i] == '>'){
			count_closing_angle_bracket++;
			domain_part_lenght +=lable_lenght;
			continue;
		}

		return 0;
	}

	if(new_label_received == false || FQDN_detected == false 
			|| buffer[i-1] != '>' || count_closing_angle_bracket != 1 ) //45 (-)
		return 0;


	return 1;
}




bool Client::ValidLocalChars(int pos)
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

bool Client::AnalyzeLocalPart(int start_position, int &domain_part_start_position, int &local_part_lenght)
{
	bool char_reseived = false, dot_received = false; 

	if(buffer[start_position] == '.' )
		return 0;
	for(int i=start_position; buffer[i] != '\r'; i++){
		if(buffer[i] == '.'){
			if(dot_received)
				return 0;
			dot_received = false;
			local_part_lenght++;
			continue;
		}
		if(buffer[i] == '@'){
			if(dot_received || char_reseived == false)
				return 0;
			domain_part_start_position = i+1;
			local_part_lenght++;
			if(local_part_lenght > MAX_LEN_LOCAL_PART_ADDR)
				return 0;
			return 1;
		}
		if(ValidLocalChars(i)){
			local_part_lenght++;
			char_reseived = true;
			dot_received = false;
			continue;
		}
		break;
	}
	//ошибки нет, но адрес пустой
	if(local_part_lenght == 0)
		return 1;
	return 0;
}


bool Client::AnalyzeMailFromArgument(int local_part_start_position)
{
	int NO_SET = -1;
	int domain_part_start_position = 0,domain_part_lenght = 0,local_part_lenght = 0,recipiet_addr_in_start_position = NO_SET;
	if(buffer[local_part_start_position] != '<'){
		return 0; 
	}
	local_part_start_position++; // первый символ прочитали, теперь старт со второго символа
			 
	//Поиск ':' - если есть, значит это source routing и выбираем только последний адрес 
	for(int i=local_part_start_position; buffer[i] != '\r'; i++){
		if(buffer[i] == ':'){
			if(recipiet_addr_in_start_position != NO_SET)
				return 0;
			recipiet_addr_in_start_position = i;
		}
	}
	if(recipiet_addr_in_start_position != NO_SET)
		local_part_start_position = recipiet_addr_in_start_position+1; //след за ':' 


	if(AnalyzeLocalPart(local_part_start_position, domain_part_start_position, local_part_lenght) == 0){
		return 0;
	}	
	//domain_part_start_position == 0 значит локальная часть была пуста, значит адреса не было!
	if(domain_part_start_position != 0 && AnalyzeDomainPart(domain_part_start_position, domain_part_lenght) == 0){
		return 0;
	}
	if(local_part_lenght + domain_part_lenght > MAX_LEN_DOMAIN){ // разобрать с длиной
		return 0;	
	}
	
	printf("%d %d\n", local_part_lenght,domain_part_lenght);
	transaction.AddAddressSender(buffer+local_part_start_position, local_part_lenght + domain_part_lenght);
	return 1;
	//доменная часть не чувствительна к регистру
}

bool Client::AnalisysMail()
{
	int argument_start_postition = 0;
	if(AnalyzeMailFrom(argument_start_postition) == 0){
		SetUnSuccessfulResponse(error_command);
		return 0;
	}
	
	ConvertToUppercase();

	if((strcmp(buffer, "MAIL FROM") == 0)){	
		if(AnalyzeMailFromArgument(argument_start_postition) == 0){
			SetUnSuccessfulResponse(error_arguments);
			return 0;
		}
		SetSuccessfulResponse(OK);
		return 1;
	}
	
	SetUnSuccessfulResponse(invalid_command);
	return 0;
}


bool Client::AnalyzeRcptToArgument(int local_part_start_position)
{
	int NO_SET = -1;
	int domain_part_start_position = 0,domain_part_lenght = 0,local_part_lenght = 0,recipiet_addr_in_start_position = NO_SET;
	
	SetUnSuccessfulResponse(error_arguments); //выставляем ошибку заранее, если ее нет, то при выходе убираем
	//Это делается чтобы иметь возможность отправлять разные ошибки

	if(buffer[local_part_start_position] != '<'){
		return 0; 
	}
	local_part_start_position++; // первый символ прочитали, теперь старт со второго символа
			 
	//Поиск ':' - если есть, значит это source routing и выбираем только последний адрес 
	for(int i=local_part_start_position; buffer[i] != '\r'; i++){
		if(buffer[i] == ':'){
			if(recipiet_addr_in_start_position != NO_SET)
				return 0;
			recipiet_addr_in_start_position = i;
		}
	}
	if(recipiet_addr_in_start_position != NO_SET)
		local_part_start_position = recipiet_addr_in_start_position+1; //след за ':' 


	if(AnalyzeLocalPart(local_part_start_position, domain_part_start_position, local_part_lenght) == 0){
		return 0;
	}	
	//Здесь локальная часть не может быть пуста, а соответсвтенно адрес должен быть!
	if(AnalyzeDomainPart(domain_part_start_position, domain_part_lenght) == 0){
		return 0;
	}
	if(local_part_lenght + domain_part_lenght > MAX_LEN_DOMAIN){ // разобрать с длиной
		return 0;	
	}
	
	printf("%d %d\n", local_part_lenght,domain_part_lenght);
	if(transaction.AddAddressRecipients(buffer+local_part_start_position, local_part_lenght + domain_part_lenght) == false){
		SetUnSuccessfulResponse(max_recipients_rcpt_to);
		//очистить все структуры?
		return 0;	
	}

	SetUnSuccessfulResponse(NULL);
	return 1;
	//доменная часть не чувствительна к регистру
}



bool Client::AnalyzeRcptTo(int &argument_start_postition)
{
	int colomn_index, open_bracket_index, close_bracket_index, current_index;

	//находим конец команды
	colomn_index = MyStrchr(buffer, ':');
	if(colomn_index == -1)
		return 0;
	buffer[colomn_index] = '\0';
	current_index = colomn_index+1;

	//Находим начало аргумента
	open_bracket_index = MyStrchr(buffer+current_index, '<');
	if(open_bracket_index == -1)
		return 0;
	argument_start_postition = open_bracket_index += current_index;
	current_index = open_bracket_index+1;

	//находим конец аргумента
	close_bracket_index = MyStrchr(buffer+current_index, '>');
	if(close_bracket_index == -1)
		return 0;
	close_bracket_index += current_index;

	//проверяем правильный порядок <>
	if(open_bracket_index > close_bracket_index)
		return 0;
	current_index = close_bracket_index+1;
						
	//проверяем что после аргумента больше нет символов	
	for(int i=current_index; buffer[i] != '\r'; i++){
		if(buffer[i] != ' ' && buffer[i] != 9)
			return 0;
	}
	
	return 1;
}


bool Client::AnalisysRCPT()
{
	int argument_start_postition = 0;
	if(AnalyzeRcptTo(argument_start_postition) == 0){
		SetUnSuccessfulResponse(error_command);
		return 0;
	}
	
	ConvertToUppercase();

	if((strcmp(buffer, "RCPT TO") == 0)){	
		if(AnalyzeRcptToArgument(argument_start_postition) == 0){
			return 0;
		}
		SetSuccessfulResponse(OK);
		return 1;
	}
	
	SetUnSuccessfulResponse(invalid_command);
	return 0;
}

bool Client::AnalisysData()
{
	int lenght_command = 0, count_word = 0;
	bool new_word = false;

	if(buffer[0] == ' ' || buffer[0] == 9){ // Если первый символ явл пробельным
		SetUnSuccessfulResponse(invalid_command);
		return 0; 
	}
	for(int i=0; buffer[i] != '\n'; i++){
		if(buffer[i] == ' ' || buffer[i] == 9 || buffer[i] == '\r'){
			if(new_word){
				new_word = false;
				count_word++;
			}
			if(count_word > 1)
				break;
			continue;
		}
		new_word = true;
		lenght_command++;
	}
	if(count_word == 0){
		SetUnSuccessfulResponse(error_command);
		return 0;
	}
	if(count_word == 1){
		buffer[lenght_command] = '\0';
		ConvertToUppercase();
		if(strcmp(buffer, "DATA") == 0){
			SetSuccessfulResponse(waiting_data);
			return 1;
		}
	}

	if(AnalisysRCPT() == 0)
		return 0;
	return 1;
}

