#include <stdio.h>
#include <unistd.h>

#include <fcntl.h>
#include <cstring>
#include <errno.h>



class Utf8{
	unsigned char *buffer;
	int count_symb;
	int size_buffer;
	char *str;

public:
	Utf8();
	~Utf8();
	void GetData();
private:
	void Analysys(int read_count);
	bool ProcessingTwoByteChar(int index, int count_oktet_for_processing, unsigned int oktet2);
	bool ProcessingThreeByteChar(int index, int count_oktet_for_processing, unsigned char oktet2, unsigned char octet3);
	bool ProcessingFourByteChar(int count_oktet_for_processing);
	bool ProcessingFourByteChar(int index, int count_oktet_for_processing, unsigned char oktet1, unsigned char oktet2, 
										unsigned char oktet3, unsigned char oktet4);
};

Utf8::Utf8()
{
	size_buffer = 20;
	buffer = new unsigned char[size_buffer];
	str = NULL;
	count_symb = 0;
}

Utf8::~Utf8()
{
	delete [] buffer;
}

void Utf8::GetData()
{
	char *cwd = new char[100];
	getcwd(cwd, 100);
	strcpy(cwd+strlen(cwd), "/kanal1");

	int fd = open(cwd, O_RDONLY);
	printf("%s\n", strerror(errno));
	int read_count = read(fd, buffer, size_buffer);
	Analysys(read_count);
	//close(fd);

}

bool Utf8::ProcessingTwoByteChar(int index, int count_oktet_for_processing, unsigned int oktet2)
{
	unsigned char cur_byte;

	cur_byte = buffer[index];
	if((cur_byte >> 6) == 2){ // 2 = 00000010
		oktet2 = (cur_byte & 0b00111111) | oktet2;
		count_oktet_for_processing--;
		count_symb++;				
		return 1;
	}
	printf("ошибка\n");
	return -1;
}

bool Utf8::ProcessingThreeByteChar(int index, int count_oktet_for_processing, unsigned char oktet2, unsigned char octet3)
{	
	unsigned char cur_byte = buffer[index];
	if((cur_byte >> 6) == 2){ // 2 = 00000010
		if(count_oktet_for_processing == 2){
			//oktet3 = (cur_byte & 0b00000011) << 6; // сохраная последние 2 бита в 2 байте и переношу на первые места
			//oktet2 = (cur_byte & 00001111) | oktet2; // устанавливаем последние 4 бита в втором байте
			count_oktet_for_processing--;
		}
		if(count_oktet_for_processing == 1){ //избыточна скорее всего  можно без if
			//oktet3 = oktet3 | cur_byte;
			count_oktet_for_processing--;
			return 1;
		}
		return 0;
	}

	return -1;
}

bool Utf8::ProcessingFourByteChar(int index, int count_oktet_for_processing, unsigned char oktet1, unsigned char oktet2, 
										unsigned char oktet3, unsigned char oktet4) 

{
	unsigned char cur_byte = buffer[index];
	if((cur_byte >> 6) == 2){ // 2 = 00000010
		if(count_oktet_for_processing == 3){
			//oktet2 = cur_byte & 0b00111111;
			count_oktet_for_processing--;
		}
		if(count_oktet_for_processing == 2){
			//oktet3 = cur_byte & 0b00111111;
			//oktet4 = (oktet3 & 0b00000011) << 6;
			//oktet3 = oktet3 >> 2;
			count_oktet_for_processing--;
		}
		if(count_oktet_for_processing == 1){ //избыточна скорее всего  можно без if
			//oktet3 = oktet3 | ((oktet2 & 0b00001111) << 4);
			//oktet2 = (oktet2 >> 4) | (octet1 << 2);
			count_oktet_for_processing--;
			return 1;
		}
		return 0;
	}

	return -1;

}

void Utf8::Analysys(int read_count)
{


	unsigned char oktet1 = 0, oktet2 = 0, oktet3 = 0, oktet4 = 0;
	int count_oktet_for_processing = 0;
	unsigned char cur_byte;
	bool two_byte_char = 0, three_byte_char = 0, four_byte_char = 0;
	for(int i=0;i<read_count;i++){
		if(two_byte_char || three_byte_char || four_byte_char){
			int result;
			if(two_byte_char) result = ProcessingTwoByteChar(i, count_oktet_for_processing, oktet2);
			else if(three_byte_char) result = ProcessingThreeByteChar(i, count_oktet_for_processing, oktet2, oktet3);
			else ProcessingFourByteChar(i,count_oktet_for_processing, oktet1, oktet2, oktet3, oktet4); 

			if(result == 1){
				two_byte_char = three_byte_char = four_byte_char = 0;
				oktet1 = oktet2 = oktet3 = oktet4 = 0;
			}
			else if(result == -1){
				count_symb = 0;
				break;
			}
			continue;
		}
		cur_byte = buffer[i];
		if((cur_byte >> 5) == 6 ){ // 6 = 1100.0000
			count_oktet_for_processing = 1; // 2 байта
			two_byte_char = 1;
			oktet1 = cur_byte & 0b00011111;
			oktet2 = (cur_byte & 0b00000011) << 6;

			continue;
		}
		else if((cur_byte >> 4) == 14){ //1110.0000
			count_oktet_for_processing = 2; // 3 байта
			three_byte_char = 1;
			//oktet1 = cur_byte & 0b00001111; // зануляю первые 4 бита в 1 байте. Октет не изпользуется
			//oktet2 = (cur_byte & 0b00001111) << 4; // сохраняю последние 4 бита в 1 байте
			
		}
		else if((cur_byte >> 3) == 30){
			count_oktet_for_processing = 3; // 4 байта
			four_byte_char = 1;
			//oktet1 = cur_byte & 0b00000111; // зануляю первые 5 бит в 1 байте. 
			//oktet2 = (cur_byte & 0b00000111) << 3; // сохраняю последние 4 бита в 1 байте

		}

		if((cur_byte >> 7) != 0){ // если первый бит не 0xxxxxxx
			printf("ошибка\n");
			break;
		}

		count_symb++;
	}
	if(two_byte_char | three_byte_char | four_byte_char){
		puts("incorrect str");
		return;
	}
	
	printf("count symb %d\n", count_symb);
	printf("count byte %d\n", read_count);
}

int main()
{

	/*char *a = new char[2];
	read(0, a, 2);
	char b = a & 192;
	printf("%c\n",b);
	if(b == 0)
		printf("ok\n");
	*/
	Utf8 obj;
	obj.GetData();
	//obj.GetData();
	//obj.GetData();


	return 1;
}



//'м' - 11010000 10111100
//	
//	110	 10
//
//	11001100
//	1. Обнуляем первые три бита в первом байте с помощью & 00011111
//	2. Получаем последние два бита в первом байте с помощью & 00000011
//	3. Сдвигаем результат 2 шага на 6 влево <<
//	4. Обнуляем первые два бита в втором байте с помощью & 00111111
//	5. Вставляем во второй байт результат 3 шага с помощью | xx000000
//
//	11010000 10111100
//
//    1.00010000
//    2.00000000
//    3.00000000
//
//
//	11001000
//   >> 00000110
