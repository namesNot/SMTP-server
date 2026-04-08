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

bool Client::AnalyzeDomain(int &domain_name_start_position, char end_str)
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
	
	for(i = domain_name_start_position+1; 1; i++){
		current_char = buffer[i];
		
		if(buffer[i+1] == end_str){
			break;
		}

		if(current_char == '[' || current_char == ']' || 
				(current_char < 47 && current_char > 58 && current_char != dot_symbol))
			return 0;

		if(current_char == dot_symbol){
			current_count_dots++;
			if(current_count_dots > max_dots_in_ip_addr || first_digit_received == 0)
				return 0;
			current_count_digits = first_digit_received = 0;
			continue;
		}

		if(first_digit_received == 0)
			first_digit_received = 1;

		current_count_digits++;

		if(current_count_digits > max_digits_per_octet)
			return 0;
	}
	
	if(current_char != ']' || current_count_dots != max_digits_per_octet || current_count_digits == 0) 
		return 0;

	return 1;
}


bool Client::AnalyzeWelcome()
{
	int start_command = 0, start_domain = 0; // or address literal [xx.x.xx.x]
			
	//отделяем команду от аргументов, команда получает последним символом '\0'
	if(AnalyzeHELO(start_command, start_domain) == 0){ 
		SetUnSuccessfulResponse(error_command);
		return 0;
	}

	ConvertToUppercase(); // Приводим команду к единому регистру

	if(strcmp(buffer, "HELO") == 0){
		if(AnalyzeDomain(start_domain, '\0') == 0){
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

