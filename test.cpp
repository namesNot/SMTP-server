#include <unistd.h>
#include <gtest/gtest.h>
#include <tuple>
#include <string>

#include "ClassMailTransaction.h"
#include "HeaderValueInfo.h"
//#include "HeaderValueParseWorkset.h"


class HeaderFromAndResentFrom: public ::testing::TestWithParam<std::tuple<std::string, std::vector<int>, std::vector<int>, bool>>
{};

TEST_P(HeaderFromAndResentFrom, ProcessingHeaderTypesAndAddressSaving)
{
	//Arrange
	MailTransaction tr;
	HeaderValueInfo addresses;
	tr.AddSizeHeaderValueInfo(addresses);
	auto tpl = GetParam();
	std::string addr = (std::get<0>(tpl));
	std::vector<int> type_addresses = (std::get<1>(tpl));
	std::vector<int> start_addresses = (std::get<2>(tpl));
	bool test_result = std::get<3>(tpl);

	for(int i = 0; i < (int)type_addresses.size(); i++){
		addresses.kinds[addresses.address_count] = (AddressKind)type_addresses[i];
		addresses.start_pos[addresses.address_count] = start_addresses[i];
		addresses.address_count++;
	}

	//Act
	bool result = tr.HeaderFrom(addr.c_str(), addr.length(), addresses);
	bool result2 = tr.HeaderResentFrom(addr.c_str(), addr.length(), addresses);

	//Assert
	ASSERT_EQ(result, test_result);
	if(result == true){
		for(int i = 0; i < (int)type_addresses.size(); i++){
			if(type_addresses[i] == 1) //name_addr
				ASSERT_STREQ(tr.headers.from[i], addr.c_str()+start_addresses[i] + 1);
			else //addr_spec
				ASSERT_STREQ(tr.headers.from[i], addr.c_str()+start_addresses[i]);
		}
	}

	ASSERT_EQ(result2, test_result);
	if(result2 == true){
		for(int i = 0; i < (int)type_addresses.size(); i++){
			if(std::get<1>(tpl)[i] == 1) //name_addr
				ASSERT_STREQ(tr.headers.resent_from[i], addr.c_str()+start_addresses[i] + 1);
			else //addr_spec
				ASSERT_STREQ(tr.headers.resent_from[i], addr.c_str()+start_addresses[i]);
		}
	}
}

INSTANTIATE_TEST_SUITE_P(
	all_cases,
	HeaderFromAndResentFrom,
	::testing::Values(		
		std::make_tuple("local@domain.ru\r\n", std::vector<int> {2}, std::vector<int> {0}, true),
		std::make_tuple("local@domain.ru, Bob <local@domain.ru\r\n>", std::vector<int> {2,1}, 
												std::vector<int> {0, 21}, true),
		std::make_tuple("local@domain.ru, CEO<local@domain.ru>, Bob <local@domain.ru\r\n>", 
								std::vector<int> {2,1,1}, std::vector<int> {0, 20, 43}, true),
		std::make_tuple("local@domain.ru, local@domain.ru, local@domain.ru\r\n>", 
								std::vector<int> {2,2,2}, std::vector<int> {0, 17, 34}, true),
		std::make_tuple("Hello <local@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 29, 52}, true),
		std::make_tuple("Hello <\"lo cal\"@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 32, 55}, true),

		std::make_tuple("Group:local@domain.ru;\r\n>", std::vector<int> {0,1}, std::vector<int> {0, 6}, false)
	)
);

class HeaderSenderAndResentSender: public ::testing::TestWithParam<std::tuple<std::string, std::vector<int>, std::vector<int>, bool>>
{};

TEST_P(HeaderSenderAndResentSender, ProcessingHeaderTypesAndAddressSaving)
{
	//Arrange
	MailTransaction tr;
	HeaderValueInfo addresses;
	tr.AddSizeHeaderValueInfo(addresses);
	auto tpl = GetParam();
	std::string addr = (std::get<0>(tpl));
	std::vector<int> type_addresses = (std::get<1>(tpl));
	std::vector<int> start_addresses = (std::get<2>(tpl));
	bool test_result = std::get<3>(tpl);

	for(int i = 0; i < (int)std::get<1>(tpl).size(); i++){
		addresses.kinds[addresses.address_count] = (AddressKind)type_addresses[i];
		addresses.start_pos[addresses.address_count] = start_addresses[i];
		addresses.address_count++;
	}

	//Act
	bool result = tr.HeaderSender(addr.c_str(), addr.length(), addresses);
	bool result2 = tr.HeaderResentSender(addr.c_str(), addr.length(), addresses);

	//Assert
	ASSERT_EQ(result, test_result);
	if(result == true){
		if(std::get<1>(tpl)[0] == 1) //name_addr
			ASSERT_STREQ(tr.headers.sender, addr.c_str()+start_addresses[0] + 1);
		else //addr_spec
			ASSERT_STREQ(tr.headers.sender, addr.c_str()+start_addresses[0]);
	}
	ASSERT_EQ(result2, test_result);
	if(result2 == true){
		if(std::get<1>(tpl)[0] == 1) //name_addr
			ASSERT_STREQ(tr.headers.resent_sender, addr.c_str()+start_addresses[0] + 1);
		else //addr_spec
			ASSERT_STREQ(tr.headers.resent_sender, addr.c_str()+start_addresses[0]);
	}
			
}

INSTANTIATE_TEST_SUITE_P(
	all_cases,
	HeaderSenderAndResentSender,
	::testing::Values(		
		std::make_tuple("local@domain.ru\r\n", std::vector<int> {2}, std::vector<int> {0}, true),

		std::make_tuple("local@domain.ru, Bob <local@domain.ru\r\n>", std::vector<int> {2,1}, 
											std::vector<int> {0, 21}, false),
		std::make_tuple("local@domain.ru, CEO<local@domain.ru>, Bob <local@domain.ru\r\n>", 
								std::vector<int> {2,1,1}, std::vector<int> {0, 20, 43}, false),
		std::make_tuple("local@domain.ru, local@domain.ru, local@domain.ru\r\n>", 
								std::vector<int> {2,2,2}, std::vector<int> {0, 17, 34}, false),
		std::make_tuple("Hello <local@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 29, 52}, false),
		std::make_tuple("Hello <\"lo cal\"@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 32, 55}, false),
		std::make_tuple("Group:local@domain.ru;\r\n>", std::vector<int> {0,1}, std::vector<int> {0, 6}, false)

	)
);


class HeaderReplyTo: public ::testing::TestWithParam<std::tuple<std::string, std::vector<int>, std::vector<int>, bool>>
{};

TEST_P(HeaderReplyTo, ProcessingHeaderTypesAndAddressSaving)
{
	//Arrange
	MailTransaction tr;
	HeaderValueInfo addresses;
	tr.AddSizeHeaderValueInfo(addresses);
	auto tpl = GetParam();
	std::string addr = (std::get<0>(tpl));
	std::vector<int> type_addresses = (std::get<1>(tpl));
	std::vector<int> start_addresses = (std::get<2>(tpl));
	bool test_result = std::get<3>(tpl);

	for(int i = 0; i < (int)std::get<1>(tpl).size(); i++){
		addresses.kinds[addresses.address_count] = (AddressKind)type_addresses[i];
		addresses.start_pos[addresses.address_count] = start_addresses[i];
		addresses.address_count++;
	}

	//Act
	bool result = tr.HeaderReplyTo(addr.c_str(), addr.length(), addresses);

	//Assert
	ASSERT_EQ(result, test_result);
	int ommitting=0;
	if(result == true){
		for(int i = 0; i < (int)std::get<1>(tpl).size(); i++){
			if((AddressKind)std::get<1>(tpl)[i] == 0){ //group
				ommitting++;
				continue;
			}
			if(std::get<1>(tpl)[i] == 1) //name_addr
				ASSERT_STREQ(tr.headers.reply_to[i-ommitting], addr.c_str()+start_addresses[i] + 1);
			else //addr_spec
				ASSERT_STREQ(tr.headers.reply_to[i-ommitting], addr.c_str()+start_addresses[i]);
		}
	}
}

INSTANTIATE_TEST_SUITE_P(
	all_cases,
	HeaderReplyTo,
	::testing::Values(		
		std::make_tuple("local@domain.ru\r\n", std::vector<int> {2}, std::vector<int> {0}, true),
		std::make_tuple("local@domain.ru, Bob <local@domain.ru\r\n>", std::vector<int> {2,1}, 
												std::vector<int> {0, 21}, true),
		std::make_tuple("local@domain.ru, CEO<local@domain.ru>, Bob <local@domain.ru\r\n>", 
								std::vector<int> {2,1,1}, std::vector<int> {0, 20, 43}, true),
		std::make_tuple("local@domain.ru, local@domain.ru, local@domain.ru\r\n>", 
								std::vector<int> {2,2,2}, std::vector<int> {0, 17, 34}, true),
		std::make_tuple("Hello <local@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 29, 52}, true),
		std::make_tuple("Hello <\"lo cal\"@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 32, 55}, true),
		std::make_tuple("Group:local@domain.ru;, \"loc al\"@domain.r.u\r\n>", 
								std::vector<int> {0,2,2}, std::vector<int> {0, 6, 24}, true),
		std::make_tuple("<local@domain.r.u>, Group:local@domain.ru;\r\n>", 
								std::vector<int> {1,0,2}, std::vector<int> {0, -1, 26}, true)

	)
);


class HeaderToCcBcc: public ::testing::TestWithParam<std::tuple<std::string, std::vector<int>, std::vector<int>, bool>>
{
protected:
	
	MailTransaction tr;
	HeaderValueInfo addresses;
	std::tuple<std::string, std::vector<int>, std::vector<int>, bool> tpl;
	std::string addr;
	std::vector<int> type_addresses, start_addresses;
	bool test_result, func_result;

	void SetUp() override{
		tr.AddSizeHeaderValueInfo(addresses);
		tpl = GetParam();
		addr = (std::get<0>(tpl));
		type_addresses = (std::get<1>(tpl));
		start_addresses = (std::get<2>(tpl));
		test_result = std::get<3>(tpl);

		for(int i = 0; i < (int)type_addresses.size(); i++){
		addresses.kinds[addresses.address_count] = (AddressKind)type_addresses[i];
		addresses.start_pos[addresses.address_count] = start_addresses[i];
		addresses.address_count++;
		}

	}
};

TEST_P(HeaderToCcBcc, ProcessingHeaderTypesForToAndAddressSaving)
{
	//Arrange

	//Act
	bool result = tr.HeaderToCcBcc(addr.c_str(), addr.length(), addresses, tr.headers, &ProcessingHeadersToRFC5322::AddTo);
	bool result2 = tr.HeaderResentToCcBcc(addr.c_str(), addr.length(), addresses, tr.headers, &ProcessingHeadersToRFC5322::AddResentTo);
	//Assert
	ASSERT_EQ(result, test_result);
	int ommitting=0;
	if(result == true){
		for(int i = 0; i < (int)type_addresses.size(); i++){
			if((AddressKind)type_addresses[i] == 0){ //group
				ommitting++;
				continue;
			}
			if(type_addresses[i] == 1) //name_addr
				ASSERT_STREQ(tr.headers.to[i-ommitting], addr.c_str() + start_addresses[i] + 1);
			else //addr_spec
				ASSERT_STREQ(tr.headers.to[i-ommitting], addr.c_str() + start_addresses[i]);
		}
	}

	ASSERT_EQ(result2, test_result);
	ommitting=0;
	if(result2 == true){
		for(int i = 0; i < (int)type_addresses.size(); i++){
			if((AddressKind)type_addresses[i] == 0){ //group
				ommitting++;
				continue;
			}
			if(type_addresses[i] == 1) //name_addr
				ASSERT_STREQ(tr.headers.resent_to[i-ommitting], addr.c_str() + start_addresses[i] + 1);
			else //addr_spec
				ASSERT_STREQ(tr.headers.resent_to[i-ommitting], addr.c_str() + start_addresses[i]);
		}
	}
}


TEST_P(HeaderToCcBcc, ProcessingHeaderTypesForCcAndAddressSaving)
{
	//Arrange


	//Act
	bool result = tr.HeaderToCcBcc(addr.c_str(), addr.length(), addresses, tr.headers, &ProcessingHeadersToRFC5322::AddCc);
	bool result2 = tr.HeaderResentToCcBcc(addr.c_str(), addr.length(), addresses, tr.headers, &ProcessingHeadersToRFC5322::AddResentCc);

	//Assert
	ASSERT_EQ(result, test_result);
	int ommitting=0;
	if(result == true){
		for(int i = 0; i < (int)type_addresses.size(); i++){
			if((AddressKind)type_addresses[i] == 0){ //group
				ommitting++;
				continue;
			}
			if(type_addresses[i] == 1) //name_addr
				ASSERT_STREQ(tr.headers.cc[i-ommitting], addr.c_str() + start_addresses[i] + 1);
			else //addr_spec
				ASSERT_STREQ(tr.headers.cc[i-ommitting], addr.c_str() + start_addresses[i]);
		}
	}

	ASSERT_EQ(result2, test_result);
	ommitting=0;
	if(result2 == true){
		for(int i = 0; i < (int)type_addresses.size(); i++){
			if((AddressKind)type_addresses[i] == 0){ //group
				ommitting++;
				continue;
			}
			if(type_addresses[i] == 1) //name_addr
				ASSERT_STREQ(tr.headers.resent_cc[i-ommitting], addr.c_str() + start_addresses[i] + 1);
			else //addr_spec
				ASSERT_STREQ(tr.headers.resent_cc[i-ommitting], addr.c_str() + start_addresses[i]);
		}
	}
}

TEST_P(HeaderToCcBcc, ProcessingHeaderTypesForBccAndAddressSaving)
{
	//Arrange


	//Act
	bool result = tr.HeaderToCcBcc(addr.c_str(), addr.length(), addresses, tr.headers, &ProcessingHeadersToRFC5322::AddBcc);
	bool result2 = tr.HeaderResentToCcBcc(addr.c_str(), addr.length(), addresses, tr.headers, &ProcessingHeadersToRFC5322::AddResentBcc);
	//Assert
	ASSERT_EQ(result, test_result);
	int ommitting=0;
	if(result == true){
		for(int i = 0; i < (int)type_addresses.size(); i++){
			if((AddressKind)type_addresses[i] == 0){ //group
				ommitting++;
				continue;
			}
			if(type_addresses[i] == 1) //name_addr
				ASSERT_STREQ(tr.headers.bcc[i-ommitting], addr.c_str()+start_addresses[i] + 1);
			else //addr_spec
				ASSERT_STREQ(tr.headers.bcc[i-ommitting], addr.c_str()+start_addresses[i]);
		}
	}

	ASSERT_EQ(result2, test_result);
	ommitting=0;
	if(result2 == true){
		for(int i = 0; i < (int)type_addresses.size(); i++){
			if((AddressKind)type_addresses[i] == 0){ //group
				ommitting++;
				continue;
			}
			if(type_addresses[i] == 1) //name_addr
				ASSERT_STREQ(tr.headers.resent_bcc[i-ommitting], addr.c_str()+start_addresses[i] + 1);
			else //addr_spec
				ASSERT_STREQ(tr.headers.resent_bcc[i-ommitting], addr.c_str()+start_addresses[i]);
		}
	}
}

INSTANTIATE_TEST_SUITE_P(
	all_cases,
	HeaderToCcBcc,
	::testing::Values(		
		std::make_tuple("local@domain.ru\r\n", std::vector<int> {2}, std::vector<int> {0}, true),
		std::make_tuple("local@domain.ru, Bob <local@domain.ru\r\n>", std::vector<int> {2,1}, 
												std::vector<int> {0, 21}, true),
		std::make_tuple("local@domain.ru, CEO<local@domain.ru>, Bob <local@domain.ru\r\n>", 
								std::vector<int> {2,1,1}, std::vector<int> {0, 20, 43}, true),
		std::make_tuple("local@domain.ru, local@domain.ru, local@domain.ru\r\n>", 
								std::vector<int> {2,2,2}, std::vector<int> {0, 17, 34}, true),
		std::make_tuple("Hello <local@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 29, 52}, true),
		std::make_tuple("Hello <\"lo cal\"@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 32, 55}, true),
		std::make_tuple("Group:local@domain.ru;, \"loc al\"@domain.r.u\r\n>", 
								std::vector<int> {0,2,2}, std::vector<int> {0, 6, 24}, true),
		std::make_tuple("<local@domain.r.u>, Group:local@domain.ru;\r\n>", 
								std::vector<int> {1,0,2}, std::vector<int> {0, -1, 26}, true)
	)
);



class HeaderMessageIDAndResentMessageID: public ::testing::TestWithParam<std::tuple<std::string, std::vector<int>, std::vector<int>, bool>>
{};

TEST_P(HeaderMessageIDAndResentMessageID, ProcessingHeaderTypesAndAddressSaving)
{
	//Arrange
	MailTransaction tr;
	HeaderValueInfo addresses;
	tr.AddSizeHeaderValueInfo(addresses);
	auto tpl = GetParam();
	std::string addr = (std::get<0>(tpl));
	std::vector<int> type_addresses = (std::get<1>(tpl));
	std::vector<int> start_addresses = (std::get<2>(tpl));
	bool test_result = std::get<3>(tpl);

	for(int i = 0; i < (int)type_addresses.size(); i++){
		addresses.kinds[addresses.address_count] = (AddressKind)type_addresses[i];
		addresses.start_pos[addresses.address_count] = start_addresses[i];
		addresses.address_count++;
	}

	//Act
	bool result = tr.HeaderMessageID(addr.c_str(), addr.length(), addresses);
	bool result2 = tr.HeaderResentMessageID(addr.c_str(), addr.length(), addresses);
	
	//Assert
	ASSERT_EQ(result, test_result);
	if(result == true){
		if(type_addresses[0] == 1) //name_addr
			ASSERT_STREQ(tr.headers.message_id, addr.c_str() + start_addresses[0] + 1);
		else //addr_spec
			ASSERT_STREQ(tr.headers.message_id, addr.c_str() + start_addresses[0]);
	}
	
	ASSERT_EQ(result2, test_result);
	if(result2 == true){
		if(type_addresses[0] == 1) //name_addr
			ASSERT_STREQ(tr.headers.resent_message_id, addr.c_str() + start_addresses[0] + 1);
		else //addr_spec
			ASSERT_STREQ(tr.headers.resent_message_id, addr.c_str() + start_addresses[0]);
	}
}
INSTANTIATE_TEST_SUITE_P(
	all_cases,
	HeaderMessageIDAndResentMessageID,
	::testing::Values(		
		std::make_tuple("<123@domain.ru>\r\n", std::vector<int> {1}, std::vector<int> {0}, true),
		std::make_tuple("Bob <123.cal@domain.ru>\r\n", std::vector<int> {1}, std::vector<int> {5}, true),
		std::make_tuple("Bob <123.cal@domain.ru>	\r\n", std::vector<int> {1}, std::vector<int> {5}, true),
		std::make_tuple("Bob <123.cal@[1.2.3.4]>\r\n", std::vector<int> {1}, std::vector<int> {5}, true),

		std::make_tuple("local@domain.ru\r\n", std::vector<int> {2}, std::vector<int> {0}, false),
		std::make_tuple("<\"local\"@domain.ru>\r\n", std::vector<int> {1}, std::vector<int> {0}, false),
		std::make_tuple("<local1@domain.ru> <dbg21@doma.in.ru>\r\n", std::vector<int> {1,1}, 
												std::vector<int> {0, 19}, false),
		std::make_tuple("local@domain.ru, Bob <local@domain.ru\r\n>", std::vector<int> {2,1}, 
											std::vector<int> {0, 21}, false),
		std::make_tuple("local@domain.ru, CEO<local@domain.ru>, Bob <local@domain.ru\r\n>", 
								std::vector<int> {2,1,1}, std::vector<int> {0, 20, 43}, false),
		std::make_tuple("local@domain.ru, local@domain.ru, local@domain.ru\r\n>", 
								std::vector<int> {2,2,2}, std::vector<int> {0, 17, 34}, false),
		std::make_tuple("Hello <local@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 29, 52}, false),
		std::make_tuple("Hello <\"lo cal\"@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 32, 55}, false),
		std::make_tuple("Group:local@domain.ru;\r\n>", std::vector<int> {0,1}, std::vector<int> {0, 6}, false)

	)
);

class HeaderInReplyTo: public ::testing::TestWithParam<std::tuple<std::string, std::vector<int>, std::vector<int>, bool>>
{};

TEST_P(HeaderInReplyTo, ProcessingHeaderTypesAndAddressSaving)
{
	//Arrange
	MailTransaction tr;
	HeaderValueInfo addresses;
	tr.AddSizeHeaderValueInfo(addresses);
	auto tpl = GetParam();
	std::string addr = (std::get<0>(tpl));
	std::vector<int> type_addresses = (std::get<1>(tpl));
	std::vector<int> start_addresses = (std::get<2>(tpl));
	bool test_result = std::get<3>(tpl);

	for(int i = 0; i < (int)type_addresses.size(); i++){
		addresses.kinds[addresses.address_count] = (AddressKind)type_addresses[i];
		addresses.start_pos[addresses.address_count] = start_addresses[i];
		addresses.address_count++;
	}

	//Act
	bool result = tr.HeaderInReplyTo(addr.c_str(), addr.length(), addresses);
	
	//Assert
	
	ASSERT_EQ(result, test_result);
	if(result == true){
		for(int i = 0; i < (int)type_addresses.size(); i++){
			if(std::get<1>(tpl)[i] == 1) //name_addr
				ASSERT_STREQ(tr.headers.in_reply_to[i], addr.c_str() + start_addresses[i] + 1);
			else //addr_spec
				ASSERT_STREQ(tr.headers.in_reply_to[i], addr.c_str() + start_addresses[i]);
		}
	}
}
INSTANTIATE_TEST_SUITE_P(
	all_cases,
	HeaderInReplyTo,
	::testing::Values(		
		std::make_tuple("<123@domain.ru>\r\n", std::vector<int> {1}, std::vector<int> {0}, true),
		std::make_tuple("Bob <123.cal@domain.ru>\r\n", std::vector<int> {1}, std::vector<int> {5}, true),
		std::make_tuple("Bob <123.cal@domain.ru>	\r\n", std::vector<int> {1}, std::vector<int> {5}, true),
		std::make_tuple("<local1@domain.ru> <dbg21@doma.in.ru>\r\n", std::vector<int> {1,1}, 
												std::vector<int> {0, 19}, true),
		std::make_tuple("Hello <local@domain.ru> <local@domain.ru> <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 24, 42}, true),
//std::make_tuple("Hello <local@domain.ru> <local@domain.ru> <local@domain.ru>\r\n>", 
//								std::vector<int> {1,1,1}, std::vector<int> {6, 24, 42}, true),

//std::make_tuple("Bob <123.cal@[1.2.3.4]>\r\n", std::vector<int> {1}, std::vector<int> {5}, true),

		std::make_tuple("local@domain.ru\r\n", std::vector<int> {2}, std::vector<int> {0}, false),
		std::make_tuple("<\"local\"@domain.ru>\r\n", std::vector<int> {1}, std::vector<int> {0}, false),
		std::make_tuple("local@domain.ru, Bob <local@domain.ru\r\n>", std::vector<int> {2,1}, 
											std::vector<int> {0, 21}, false),
		std::make_tuple("local@domain.ru, CEO<local@domain.ru>, Bob <local@domain.ru\r\n>", 
								std::vector<int> {2,1,1}, std::vector<int> {0, 20, 43}, false),
		std::make_tuple("local@domain.ru, local@domain.ru, local@domain.ru\r\n>", 
								std::vector<int> {2,2,2}, std::vector<int> {0, 17, 34}, false),
		std::make_tuple("Hello <\"lo cal\"@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 32, 55}, false),
		std::make_tuple("Group:local@domain.ru;\r\n>", std::vector<int> {0,1}, std::vector<int> {0, 6}, false)
	)
);


class HeaderReferences: public ::testing::TestWithParam<std::tuple<std::string, std::vector<int>, std::vector<int>, bool>>
{};

TEST_P(HeaderReferences, ProcessingHeaderTypesAndAddressSaving)
{
	//Arrange
	MailTransaction tr;
	HeaderValueInfo addresses;
	tr.AddSizeHeaderValueInfo(addresses);
	auto tpl = GetParam();
	std::string addr = (std::get<0>(tpl));
	std::vector<int> type_addresses = (std::get<1>(tpl));
	std::vector<int> start_addresses = (std::get<2>(tpl));
	bool test_result = std::get<3>(tpl);

	for(int i = 0; i < (int)type_addresses.size(); i++){
		addresses.kinds[addresses.address_count] = (AddressKind)type_addresses[i];
		addresses.start_pos[addresses.address_count] = start_addresses[i];
		addresses.address_count++;
	}

	//Act
	bool result = tr.HeaderReferences(addr.c_str(), addr.length(), addresses);
	
	//Assert
	
	ASSERT_EQ(result, test_result);
	if(result == true){
		for(int i = 0; i < (int)type_addresses.size(); i++){
			if(type_addresses[i] == 1) //name_addr
				ASSERT_STREQ(tr.headers.references[i], addr.c_str() + start_addresses[i] + 1);
			else //addr_spec
				ASSERT_STREQ(tr.headers.references[i], addr.c_str() + start_addresses[i]);
		}
	}
}
INSTANTIATE_TEST_SUITE_P(
	all_cases,
	HeaderReferences,
	::testing::Values(		
		std::make_tuple("<123@domain.ru>\r\n", std::vector<int> {1}, std::vector<int> {0}, true),
		std::make_tuple("Bob <123.cal@domain.ru>\r\n", std::vector<int> {1}, std::vector<int> {5}, true),
		std::make_tuple("Bob <123.cal@domain.ru>	\r\n", std::vector<int> {1}, std::vector<int> {5}, true),
		std::make_tuple("<local1@domain.ru> <dbg21@doma.in.ru>\r\n", std::vector<int> {1,1}, 
												std::vector<int> {0, 19}, true),
		std::make_tuple("Hello <local@domain.ru> <local@domain.ru> <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 24, 42}, true),
//std::make_tuple("Hello <local@domain.ru> <local@domain.ru> <local@domain.ru>\r\n>", 
//								std::vector<int> {1,1,1}, std::vector<int> {6, 24, 42}, true),

//std::make_tuple("Bob <123.cal@[1.2.3.4]>\r\n", std::vector<int> {1}, std::vector<int> {5}, true),

		std::make_tuple("local@domain.ru\r\n", std::vector<int> {2}, std::vector<int> {0}, false),
		std::make_tuple("<\"local\"@domain.ru>\r\n", std::vector<int> {1}, std::vector<int> {0}, false),
		std::make_tuple("local@domain.ru, Bob <local@domain.ru\r\n>", std::vector<int> {2,1}, 
											std::vector<int> {0, 21}, false),
		std::make_tuple("local@domain.ru, CEO<local@domain.ru>, Bob <local@domain.ru\r\n>", 
								std::vector<int> {2,1,1}, std::vector<int> {0, 20, 43}, false),
		std::make_tuple("local@domain.ru, local@domain.ru, local@domain.ru\r\n>", 
								std::vector<int> {2,2,2}, std::vector<int> {0, 17, 34}, false),
		std::make_tuple("Hello <\"lo cal\"@domain.ru>, Bob <local@domain.ru>, CEO <local@domain.ru>\r\n>", 
								std::vector<int> {1,1,1}, std::vector<int> {6, 32, 55}, false),
		std::make_tuple("Group:local@domain.ru;\r\n>", std::vector<int> {0,1}, std::vector<int> {0, 6}, false)
	)
);


class DateTime: public ::testing::TestWithParam<std::tuple<std::string, bool>>
{};

TEST_P(DateTime, ProcessingHeaderAndAddressSaving)
{
	//Arrange
	MailTransaction tr;
	auto tpl = GetParam();
	std::string addr = (std::get<0>(tpl));
	bool test_result = std::get<1>(tpl);

	//Act
	//Проверяю сразу два заголовка
	int result = tr.DateTime(addr.c_str(), addr.length(), tr.headers, &ProcessingHeadersToRFC5322::AddDate);
	int result2 = tr.DateTime(addr.c_str(), addr.length(), tr.headers, &ProcessingHeadersToRFC5322::AddResentDate);

	//Assert
	ASSERT_EQ(result, test_result);
	ASSERT_EQ(result2, test_result);
	if(result == true){
		ASSERT_STREQ(tr.headers.orig_date, addr.c_str());
		ASSERT_STREQ(tr.headers.resent_date, addr.c_str());
	}
	else{
		ASSERT_STREQ(tr.headers.orig_date, NULL);
		ASSERT_STREQ(tr.headers.resent_date, NULL);
	}

}
INSTANTIATE_TEST_SUITE_P(
	correct_cases,
	DateTime,
	::testing::Values(		
		std::make_tuple("Tue, 15 May 1994 23:45:34 +1000\r\n", true),
		std::make_tuple("   Tue, 15 May 1994 23:45:34 +1000\r\n", true),
		std::make_tuple("Tue, 15 May 1994 23:45:34 +1000\r\n", true),

		std::make_tuple("00 May 1994 23:45:34 +1000\r\n", true),
		std::make_tuple("01 May 1994 23:45:34 +1000\r\n", true),
		std::make_tuple("15 May 1994 23:45:34 +1000\r\n", true),
		std::make_tuple("	15 	May 1994 23:45:34 +1000\r\n", true),
		std::make_tuple("31 May 1994 23:45:34 +1000\r\n", true),

		std::make_tuple("25 Jan 2000 12:30:10 +1000\r\n", true),
		std::make_tuple("25 	Jan  2000 12:30:10 +1000\r\n", true),

		std::make_tuple("10 Feb 1900 12:30:10 +1000\r\n", true),
		std::make_tuple("10 Feb 9999    12:30:10 +1000\r\n", true),

		std::make_tuple("Mon, 18 Mar 2010 00:00 +1000\r\n", true),
		std::make_tuple(" Mon, 18 Mar 2010 23:59     +1000\r\n", true),
		std::make_tuple("Mon, 18 Mar 2010 00:00:00 +1000\r\n", true),
		std::make_tuple("Mon, 18 Mar 2010 23:59:59  +1000\r\n", true),

		std::make_tuple("Wed, 26 Aug 2020 23:45:00 	+0000\r\n", true),
		std::make_tuple("Wed, 26 Aug 2020 23:45:00 	-1000\r\n", true),
		std::make_tuple("Wed, 26 Aug 2020 23:45:00 	+2359\r\n", true),
		std::make_tuple("Wed, 26 Aug 2020 23:45:00 	+1230   \r\n", true)
	)
);

INSTANTIATE_TEST_SUITE_P(
	uncorrect_cases,
	DateTime,
	::testing::Values(		
		std::make_tuple("Tue , 15 May 1994 23:45:34 +1000\r\n", false),
		std::make_tuple(", 15 May 1994 23:45:34 +1000\r\n", false),
		std::make_tuple("Tuen, 15 May 1994 23:45:34 +1000\r\n", false),
		std::make_tuple("Tue. 15 May 1994 23:45:34 +1000\r\n", false),
		std::make_tuple("Tue 15 May 1994 ,23:45:34 +1000\r\n", false),

		std::make_tuple("0 May 1994 23:45:34 +1000\r\n", false),
		std::make_tuple("1 May 1994 23:45:34 +1000\r\n", false),
		std::make_tuple("32 May 1994 23:45:34 +1000\r\n", false),
		std::make_tuple("-1 May 1994 23:45:34 +1000\r\n", false),
		std::make_tuple("123 May 1994 23:45:34 +1000\r\n", false),

		std::make_tuple("25 Janc 2000 12:30:10 +1000\r\n", false),
		std::make_tuple("25 Jan 12 2000 12:30:10 +1000\r\n", false),
		std::make_tuple("25 jan 2000 12:30:10 +1000\r\n", false),

		std::make_tuple("10 Feb 20 00 12:30:10 +1000\r\n", false),
		std::make_tuple("10 Feb 19000 12:30:10 +1000\r\n", false),

		std::make_tuple("Mon, 18 Mar 2010 1:00:00 +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 00:0:00 +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 00:00:0 +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 24:00 +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 23:60 +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 00:00:60 +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 23:450:00 +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 23 :45 :00 +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 23: 45: 00 +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 23:: +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 23 +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 23:-10:00 +1000\r\n", false),
		std::make_tuple("Mon, 18 Mar 2010 23:00:-1 +1000\r\n", false),

		std::make_tuple("Wed, 26 Aug 2020 23:45:00 +2459\r\n", false),
		std::make_tuple("Wed, 26 Aug 2020 23:45:00 +2360\r\n", false),
		std::make_tuple("Wed, 26 Aug 2020 23:45:00 + 1000\r\n", false),
		std::make_tuple("Wed, 26 Aug 2020 23:45:00 - 1000\r\n", false),
		std::make_tuple("Wed, 26 Aug 2020 23:45:00 *1000\r\n", false),
		std::make_tuple("Wed, 26 Aug 2020 23:45:00 +10 00\r\n", false),
		std::make_tuple("Wed, 26 Aug 2020 23:45:00 +1 000\r\n", false),
		std::make_tuple("Wed, 26 Aug 2020 23:45:00+1000\r\n", false),


		std::make_tuple("10Feb1900 12:30:10 +1000\r\n", false),
		std::make_tuple("Feb 10 1900 12:30:10 +1000\r\n", false),
		std::make_tuple("10 Feb 190012:30:10 +1000\r\n", false),

		std::make_tuple("Tue, 15 May 1994 23:45:34 +1000 wqe\r\n", false)
	)
);

class HeaderSubjectCommentsKeywords: public ::testing::TestWithParam<std::tuple<std::string, bool>>
{};

TEST_P(HeaderSubjectCommentsKeywords, CheckSavingHeader){
	//Arrange
	MailTransaction tr;
	auto tpl = GetParam();
	std::string addr = (std::get<0>(tpl));
	bool test_result = std::get<1>(tpl);

	//Act
	int result1 = tr.headers.AddSubject(addr.c_str(), addr.length()); 
	int result2 = tr.headers.AddComments(addr.c_str(), addr.length()); 
	int result3 = tr.headers.AddKeywords(addr.c_str(), addr.length());
	
	//Assert
	ASSERT_EQ(result1, test_result);
		ASSERT_STREQ(tr.headers.subject, addr.c_str());
	ASSERT_EQ(result2, test_result);
		ASSERT_STREQ(tr.headers.comments, addr.c_str());
	ASSERT_EQ(result3, test_result);
		ASSERT_STREQ(tr.headers.keywords, addr.c_str());
}

INSTANTIATE_TEST_SUITE_P(
	correct_cases,
	HeaderSubjectCommentsKeywords,
	::testing::Values(
		std::make_tuple("vjsdfbkjdsb b sdgb \"vdf\"vdfvf\r\n", true)
		)		
);

class AnalyzeLocalPartForFields: public ::testing::TestWithParam<std::tuple<std::string, bool, int, int>>
{};

TEST_P(AnalyzeLocalPartForFields, CheckCorrectLocalPart)
{
	//Arrange
	MailTransaction tr;
	auto tpl = GetParam();
	const char *addr = (std::get<0>(tpl)).c_str();
	bool test_result = std::get<1>(tpl);
	//int local_part_length = std::get<2>(tpl);
	int domain_part_start_position = std::get<3>(tpl);
	int actual_local_part_length = 0, actual_domain_part_start_position = 0;


	//Act
	bool result = tr.AnalyzeLocalPartForFields(addr, 0, actual_domain_part_start_position, actual_local_part_length);

	//Assert
	ASSERT_EQ(result, test_result);
	//ASSERT_EQ(actual_local_part_length, local_part_length);
	ASSERT_EQ(actual_domain_part_start_position, domain_part_start_position);

}

INSTANTIATE_TEST_SUITE_P(
	all_cases_for_dot_atom_for_local_part,
	AnalyzeLocalPartForFields,
	::testing::Values(		
		std::make_tuple("local@domain.ru\r\n", true, 5, 6),
		std::make_tuple("lOcaL@domain.ru\r\n", true, 5, 6),
		std::make_tuple("LOCAL@domain.ru\r\n", true, 5, 6),
		std::make_tuple("abc123@domain.ru\r\n", true, 6, 7),
		std::make_tuple("lo.cal@domain.ru\r\n", true, 6, 7),
		std::make_tuple("user+tag@domain.ru\r\n", true, 8, 9),
		std::make_tuple("!def!/xyz=abc@domain.ru\r\n", true, 13, 14),
		std::make_tuple("user_name@domain.ru\r\n", true, 9, 10),
		std::make_tuple("user-name@domain.ru\r\n", true, 9, 10),


		std::make_tuple("usernamedomain.ru\r\n", false, 0, 0),
		std::make_tuple("user..name@domain.ru\r\n", false, 0, 0),
		std::make_tuple("user.@domain.ru\r\n", false, 0, 0),
		std::make_tuple(".user@domain.ru\r\n", false, 0, 0),
		std::make_tuple("user name@domain.ru\r\n", false, 0, 0),
		std::make_tuple("user,name@domain.ru\r\n", false, 0, 0),
		std::make_tuple("user<name>@domain.ru\r\n", false, 0, 0),
		std::make_tuple("user(name)@domain.ru\r\n", false, 0, 0)
	)
);

INSTANTIATE_TEST_SUITE_P(
	all_cases_for_quoted_string_for_local_part,
	AnalyzeLocalPartForFields,
	::testing::Values(		
		std::make_tuple("\"local\"@domain.ru\r\n", true, 7, 8),
		std::make_tuple("\"lo.cal\"@domain.ru\r\n", true, 8, 9),
		std::make_tuple("\"lo..cal\"@domain.ru\r\n", true, 9, 10),
		std::make_tuple("\"loc al\"@domain.ru\r\n", true, 8, 9),
		std::make_tuple("\"	loc al\"@domain.ru\r\n", true, 9, 10),
		std::make_tuple("\"abc@\"@domain.ru\r\n", true, 6, 7),
		std::make_tuple("\"nam\\\"e\"@domain.ru\r\n", true, 8, 9),
		std::make_tuple("\"a@b\"@domain.ru\r\n", true, 5, 6),
		std::make_tuple("\"lo\\\"cal\"@domain.ru\r\n", true, 9, 10),
		std::make_tuple("\"backslash\\\\test\"@domain.ru\r\n", true, 17, 18),

		std::make_tuple("\"user.@domain.ru\r\n", false, 0, 0),
		std::make_tuple("user\"@domain.ru\r\n", false, 0, 0),
		//std::make_tuple("\"user имя\"@domain.ru\r\n", false, 0, 0),
		std::make_tuple("\"user,\"name@domain.ru\r\n", false, 0, 0),
		std::make_tuple("user\"name\"@domain.ru\r\n", false, 0, 0),
		std::make_tuple("user(name)domain.ru\r\n", false, 0, 0)
	)
);



class AnalyzeDomainPartForFields: public ::testing::TestWithParam<std::tuple<std::string, bool, int, int>>
{};

TEST_P(AnalyzeDomainPartForFields, CheckCorrectDomainPart)
{
	//Arrange
	MailTransaction tr;
	auto tpl = GetParam();
	const char *addr = (std::get<0>(tpl)).c_str();
	bool test_result = std::get<1>(tpl);
	int domain_part_start_position = std::get<2>(tpl), domain_part_length  = std::get<3>(tpl);
	int actual_domain_part_length = 0;


	//Act
	bool result = tr.AnalyzeDomainPartForFields(addr, domain_part_start_position, actual_domain_part_length);

	//Assert
	ASSERT_EQ(result, test_result);
	ASSERT_EQ(actual_domain_part_length, domain_part_length);

}

INSTANTIATE_TEST_SUITE_P(	
	all_cases_for_dot_atom_for_domain_part,
	AnalyzeDomainPartForFields,
	::testing::Values(		
		std::make_tuple("local@domain.ru\r\n", true, 6, 9),
		std::make_tuple("local@sub.domain.ru\r\n", true, 6, 13),
		std::make_tuple("local@sub-domain.ru\r\n", true, 6, 13),
		std::make_tuple("local@a-b-c-domain.ru\r\n", true, 6, 15),
		std::make_tuple("local@domain.ru,", true, 6, 9),
		std::make_tuple("local@domain.ru   ,", true, 6, 9),
		std::make_tuple("local@domain.ru;", true, 6, 9),
		std::make_tuple("local@domain.ru   ;", true, 6, 9),
		std::make_tuple("local@domain.ru,", true, 6, 9),
		std::make_tuple("local@domain.ru   ,", true, 6, 9),
		std::make_tuple("local@domain.ru  \r\n", true, 6, 9),

		std::make_tuple("local@domain\r\n", false, 0, 0),
		std::make_tuple("local@domain..ru\r\n", false, 0, 0),
		std::make_tuple("local@.domain.ru\r\n", false, 0, 0),
		std::make_tuple("local@domain.ru.\r\n", false, 0, 0),
		std::make_tuple("local@domain,ru\r\n", false, 0, 0),
		std::make_tuple("local@domain!ru\r\n", false, 0, 0),
		std::make_tuple("local@domain.   ru\r\n", false, 0, 0),
		std::make_tuple("local@do\\main\r\n", false, 0, 0),
		std::make_tuple("local@dom\"ain\r\n", false, 0, 0),
		std::make_tuple("local@\"domain\"\r\n", false, 0, 0)
		
	)
);

INSTANTIATE_TEST_SUITE_P(	
	all_cases_for_domain_literal_for_domain_part,
	AnalyzeDomainPartForFields,
	::testing::Values(		
		std::make_tuple("local@[1.2.3.4]\r\n", true, 6, 9),
		std::make_tuple("local@[255.255.255.255]\r\n", true, 6, 17),
		std::make_tuple("local@[999.999.999.999]   \r\n", true, 6, 17),
		std::make_tuple("local@[0.0.0.0]\r\n", true, 6, 9),
		std::make_tuple("local@[123.234.111.123],\r\n", true, 6, 17),
		std::make_tuple("local@[123.234.111.123];\r\n", true, 6, 17),
		std::make_tuple("local@[123.234.111.123],\r\n", true, 6, 17),
		std::make_tuple("local@[123.234.111.123]>\r\n", true, 6, 17),
		std::make_tuple("local@[123.234.111.123]  ,\r\n", true, 6, 17),
		std::make_tuple("local@[123.234.111.123]  ;\r\n", true, 6, 17),
		std::make_tuple("local@[123.234.111.123]  ,\r\n", true, 6, 17),
		std::make_tuple("local@[123.234.111.123]   >\r\n", true, 6, 17),
		std::make_tuple("local@[123.234.111.123]   >   \r\n", true, 6, 17),
		

		std::make_tuple("local@[1.2.3.4\r\n", false, 0, 0),
		std::make_tuple("local@1.2.3.4]\r\n", false, 0, 0),
		std::make_tuple("local@1.2.3.4.3]\r\n", false, 0, 0),
		std::make_tuple("local@1.2.3.e]\r\n", false, 0, 0),
		std::make_tuple("local@1.2.3.4]1\r\n", false, 0, 0),
		std::make_tuple("local@1.2.3.4]\r\n", false, 0, 0),
		std::make_tuple("local@[1.2].3.4]\r\n", false, 0, 0),
		std::make_tuple("local@[1.2.3.[4]\r\n", false, 0, 0),
		std::make_tuple("local@[1123.2.3.4]\r\n", false, 0, 0),
		std::make_tuple("local@[1.2.4]\r\n", false, 0, 0),
		std::make_tuple("local@[12.3.4]\r\n", false, 0, 0),
		std::make_tuple("local@[1.2..4]\r\n", false, 0, 0),
		std::make_tuple("local@[1.-2.3.4]\r\n", false, 0, 0),
		std::make_tuple("local@[1.2.3.v]\r\n", false, 0, 0),
		std::make_tuple("local@[123.234.111.123] 6   >   \r\n", false, 0, 0),
		std::make_tuple("local@[123.234.111.123]> j  \r\n", false, 0, 0)
	)
);


class IdentificationFields: public ::testing::TestWithParam<std::tuple<std::string, int, bool>>
{};

TEST_P(IdentificationFields, CheckingStructureOfTheIdentificationField)
{
	//Arrange
	MailTransaction tr;
	HeaderValueInfo addresses;
	tr.AddSizeHeaderValueInfo(addresses);
	auto tpl = GetParam();
	char *str = new char[std::get<0>(tpl).length() + 1];
	strcpy(str,(char*)std::get<0>(tpl).c_str());
	int count_addresses = std::get<1>(tpl);
	bool test_result = std::get<2>(tpl);

	//Act
	bool result = tr.IdentificationFields(str, addresses);

	//Assert
	ASSERT_EQ(result, test_result);
	if(result == true){
		ASSERT_EQ(addresses.address_count, count_addresses);
	}

}	

INSTANTIATE_TEST_SUITE_P(
	AllCases,
	IdentificationFields,
	::testing::Values(
		std::make_tuple("<local@domain.ru>\r\n",1, true),
		std::make_tuple("<addr>\r\n",1, true),
		std::make_tuple("<addr1> <addr2>\r\n", 2, true),
		std::make_tuple("<addr>\t<addr2> \r\n", 2, true),
		std::make_tuple("<addr>   <addr2>\r\n", 2, true),
		std::make_tuple("<addr> <addr2>\t<addr3>\r\n", 3, true),
		std::make_tuple("<addr><addr2>\t<addr3>\r\n", 3, true),
		std::make_tuple("<addr> <>\r\n",2, true),
		std::make_tuple("<addr><addr2>\r\n", 2, true),
	
		std::make_tuple("<\"user name\"@domain.ru>\r\n",1, false),
		std::make_tuple("<local@[11.22.33.44]>\r\n",1, false),
		
		std::make_tuple("addr_spec\r\n",1, false),
		std::make_tuple("addr>\r\n",1, false),
		std::make_tuple("<addr\r\n",1, false),
		std::make_tuple(">addr\r\n",1, false),
		std::make_tuple("<addr<\r\n",1, false),
		std::make_tuple("<addr>,<addr2>\r\n", 2, false),
		std::make_tuple("CEO <addr>\r\n", 2, false),
		std::make_tuple("CEO <addr>  Bob <addr2>\r\n", 2, false),
		std::make_tuple("\"CEO\" <addr><addr2>\r\n", 2, false)
	)
);

class ParseAddressHeaderField: public ::testing::TestWithParam<std::tuple<std::string, bool>>
{};

TEST_P(ParseAddressHeaderField, CheckStructAddressList)
{
	//Arrange
	MailTransaction tr;
	HeaderValueInfo addresses;
	tr.AddSizeHeaderValueInfo(addresses);
	auto tpl = GetParam();
	const char *str = (std::get<0>(tpl)).c_str();
	bool test_result = (std::get<1>(tpl));

	//Act
	bool result = tr.ParseAddressHeaderField(str, addresses);
	
	//Assert
	ASSERT_EQ(result, test_result);
	
}
INSTANTIATE_TEST_SUITE_P(
	addr_spec_all_cases,
	ParseAddressHeaderField,
	::testing::Values(
		std::make_tuple("local@domain.ru\r\n", true),
		std::make_tuple("\"local\"@domain.ru\r\n", true),
		std::make_tuple("\"loc\\\"al\"@domain.ru\r\n", true),
		std::make_tuple("\"Bob\" @domain.ru\r\n", true),
		std::make_tuple("any addr, any addr \r\n", true),
		std::make_tuple("any addr ,any addr \r\n", true),
		std::make_tuple("local@domain.ru local\r\n", true), //пропустит,тк это будет addr_spec 
		std::make_tuple("local @domain.ru\r\n", true),//пропустит,тк это будет addr_spec 
								//он будет проверяться в след функциях будет выявит ошибку
		std::make_tuple("local@domain.ru, \r\n", false),
		std::make_tuple(",local@domain.ru \r\n", false),
		std::make_tuple("local@domain.ru; \r\n", false),
		std::make_tuple("<name_addr> local@domain.ru \r\n", false),
		std::make_tuple("(comment) local@domain.ru \r\n", false),
		std::make_tuple("(comment local@domain.ru; \r\n", false),
		std::make_tuple("local@domain.ru\" \r\n", false),
		std::make_tuple("\"local@domain.ru \r\n", false),
		std::make_tuple("local\\@domain \r\n", false),
		std::make_tuple("local@domain\\\r\n", false)
	)
);

INSTANTIATE_TEST_SUITE_P(
	name_addr_all_cases,
	ParseAddressHeaderField,
	::testing::Values(		
		std::make_tuple("< local@domain.ru>\r\n", true),
		std::make_tuple("<local@domain.ru>\r\n", true),
		std::make_tuple("<anything>\r\n", true),
		std::make_tuple("<local@domain> ,CEO <local@domain.ru> \r\n", true),
		std::make_tuple("   <local@domain>, CEO <local@domain.ru> \r\n", true),
		std::make_tuple("<\"local\"@domain.ru>\r\n", true),
		std::make_tuple("(comment) Bob <any_addr>\r\n", true), 
		std::make_tuple("(comment) \"text\" Bob <any_addr>\r\n", true),
		std::make_tuple("(comment<vfd@vfd.v) Bob <any_addr>\r\n", true), 
		std::make_tuple("	Bob <any_addr>\r\n", true),
		std::make_tuple("(comment\")<any addr>	\r\n", true),
		std::make_tuple("(comment\\))<any addr>	\r\n", true),
		std::make_tuple("(comment(comment)) <any addr>\r\n", true),
		std::make_tuple("<> \r\n", true),
		
	
		std::make_tuple("<local@domain.ru> Bob (comment)\r\n", true), // Такие варианты отработают, но функции по анализу
		std::make_tuple("\"CEO\" <local@domain.ru> \"Bob\"\r\n", true), //локальной и доменной части выдадут ошибку, тк
		std::make_tuple("<local@domain.ru> addr-spec\r\n", true), // после name_addr не может быть ничего кроме ,\r;<

		std::make_tuple("<local@domain.ru\\>> \r\n", false),
		std::make_tuple("<local@domain.ru>  <bdf>\r\n", false),
		std::make_tuple("<local@domain.ru\r\n", false),
		std::make_tuple("local@domain.ru>\r\n", false),
		std::make_tuple("<local@domain.ru\r\n", false),
		std::make_tuple(">local@domain.ru>\r\n", false),
		std::make_tuple("<local@domain.ru<\r\n", false),
		std::make_tuple("\"Bo<any addr>\r\n", false),
		std::make_tuple("(comment))<any addr>\r\n", false),
		std::make_tuple("((comment) <any addr>\r\n", false),
		std::make_tuple("<local\\@domain.ru>\r\n", false),
		std::make_tuple(" \\<<any addr>\r\n", false)
		
	)
);

INSTANTIATE_TEST_SUITE_P(
	Group,
	ParseAddressHeaderField,
	::testing::Values(
		std::make_tuple("group:local@domain;\r\n", true),
		std::make_tuple("\"group\":local@domain;\r\n", true),
		std::make_tuple("group:addr1, addr2;\r\n", true),
		std::make_tuple("group: <addr1> ;\r\n", true),
		std::make_tuple("group: <addr1> , <addr2>; \r\n", true),
		std::make_tuple("group : addr1;\r\n", true),
		std::make_tuple("group: addr1, <addr2>; \r\n", true),
		std::make_tuple("group: <addr1>, addr2; \r\n", true),
		std::make_tuple("group:local@domain;, addr2\r\n", true),
		std::make_tuple("group:<addr1>;	,group2:addr2;\r\n", true),
		std::make_tuple("group:<addr1>;,group2:addr2;\r\n", true),
		


		std::make_tuple("group:local@domain\r\n", false),
		std::make_tuple("group:local@domain, \r\n", false),
		std::make_tuple("group:local@domain,; \r\n", false),
		std::make_tuple("local@domain; \r\n", false),
		std::make_tuple("local@domain; \r\n", false),
		std::make_tuple("group:local@domain; addr2\r\n", false),
		std::make_tuple("(comment) group:local@domain;\r\n", false),
		std::make_tuple(" <group>:local@domain;\r\n", false),
		std::make_tuple("group\\:<addr1>;,group2:addr2;\r\n", false)
		)
);


class SeparateUnfoldingHeader: public ::testing::TestWithParam<std::tuple<std::string, std::string, bool>>
{};

TEST_P(SeparateUnfoldingHeader, CheckCorrectUnfolding)
{
	//Arrange
	MailTransaction tr;
	auto tpl = GetParam();
	const char *folding_str = (std::get<0>(tpl)).c_str();
	int len_folding_str = (std::get<0>(tpl)).length();
	const char *expected_unfolding_str = (std::get<1>(tpl)).c_str();
        char *unfolding_str = new char[len_folding_str+1];
	bool test_result = (std::get<2>(tpl));
	
	//Act
	int result = tr.SeparateUnfoldingHeader(folding_str, unfolding_str, len_folding_str);
	
	//Assert
	ASSERT_EQ(result, test_result);
	if(result == true){
		ASSERT_STREQ(unfolding_str, expected_unfolding_str);
	}
}
INSTANTIATE_TEST_SUITE_P(
	AllCases,
	SeparateUnfoldingHeader,
	::testing::Values(
		std::make_tuple("header:address \r\n", "header:address \r\n", true),
		std::make_tuple("header:address1\r\n address2\r\n", "header:address1 address2\r\n", true),
		std::make_tuple("header:address1 \r\n	address2\r\n", "header:address1  address2\r\n", true),
		std::make_tuple("addr \r\n addr\r\n add\r\n", "addr  addr add\r\n", true),
		std::make_tuple("address\r\n    \r\n", "address    \r\n", true),
		std::make_tuple("<loca\r\n l@domain.ru>\r\n", "<loca l@domain.ru>\r\n", true),
		std::make_tuple("Bob <any_addr>,\r\n <local@domain.ru>\r\n", "Bob <any_addr>, <local@domain.ru>\r\n", true), 
		std::make_tuple("local@domain.ru,\r\n local@domain.ru\r\n", "local@domain.ru, local@domain.ru\r\n", true),
		std::make_tuple("\"local\r\n \"@domain.ru \r\n", "\"local \"@domain.ru \r\n", true),
		std::make_tuple("head\\er:addr\\ess \r\n", "head\\er:addr\\ess \r\n", true),


		std::make_tuple("\r\n", "", false),
		std::make_tuple("address\r \r\n", "", false),
		std::make_tuple("address\n \r\n", "", false),
		std::make_tuple("\r\n address\r\n", "", false),
		std::make_tuple("address\r\n \r\n \r\n", "", false)
	)
);



class FindNextHeaderField: public ::testing::TestWithParam<std::tuple<std::string, int, int>>
{};

TEST_P(FindNextHeaderField, DetectsEndOfHeader){
	//Arrange
	MailTransaction tr;
	auto tpl = GetParam();
	int test_result = std::get<2>(tpl);
	const char *str = (std::get<0>(tpl)).c_str();
	strcpy(tr.mail_data, str);
	int len = (std::get<0>(tpl)).length();
	tr.AppendMailData(str, len);

	//Act
	int end_index_header = 0;
	int result = tr.FindNextHeaderField(0, end_index_header);

	//Assert
	ASSERT_EQ(result, test_result);
	ASSERT_EQ(end_index_header,(std::get<1>(tpl)));
	ASSERT_NE(tr.mail_data, nullptr);

}

INSTANTIATE_TEST_SUITE_P(
	AllCases,
	FindNextHeaderField,
	::testing::Values(
		std::make_tuple("header:address\r\nheader...", 15 ,1),
		std::make_tuple("header:address\r\n header...\r\nheader...", 27, 1),
		std::make_tuple("header:address  \r\n.\r\n", 17, 1), //конец заголовка
		std::make_tuple("header:address  \r\n \r\nheader..", 20, 1),
		std::make_tuple("header: address\r\n\r\n", 16, 0),
		std::make_tuple("header: address\r\n\r\n data", 16, 0),

		std::make_tuple("\r\n",0, -1),
		std::make_tuple("\r\n\r\n data \r\n.\r\n", 0, -1),
		std::make_tuple("header:address  \r\n \r\n", 0, -1)
	)
);

TEST(AppendMailData, IncreasingTheMailBuffer)
{
	//Arrange1
	int len, result;
	char *buffer = new char[100];
	MailTransaction tr;
	strcpy(buffer, "address address");
	len = strlen("address address");
	
       	tr.mail_data_size = 90;

	//Act1
	result = tr.AppendMailData(buffer, len);

	//Assert1
	ASSERT_EQ(result, 90 + len);
	ASSERT_EQ(tr.mail_data_max_size, 200);
}


TEST(AppendMailData, AddingData)
{
	//Arrange1
	int len, result;
	char *buffer = new char[100];
	MailTransaction tr;
	strcpy(buffer, "address address");
	len = strlen("address address");

	//Act1
	result = tr.AppendMailData(buffer, len);

	//Assert1
	ASSERT_EQ(result, len);
	
	//Arrange2
	buffer[0] = '\0';
	strcpy(buffer, "address address");
	len = strlen("address address");

	//Act2
	result = tr.AppendMailData(buffer, len);

	//Assert2
	ASSERT_EQ(result, len+len);
}


class FindEndOfMailData: public ::testing::TestWithParam<std::tuple<std::string,std::string, int>>
{};

TEST_P(FindEndOfMailData, DetectsEndOfData){
	//Arrange
	MailTransaction tr;
	int result;
	auto tpl = GetParam();
	std::string string1 = std::get<0>(tpl);
	std::string string2 = std::get<1>(tpl);
	int test_result = std::get<2>(tpl); 
	
	//Act
	tr.FindEndOfMailData(string1.c_str(), string1.length());
	result = tr.FindEndOfMailData(string2.c_str(), string2.length());

	//Assert
	ASSERT_EQ(result, test_result);
}

INSTANTIATE_TEST_SUITE_P(
	ValidCases,
	FindEndOfMailData,
	::testing::Values(
		std::make_tuple("", "text \r\n.\r\n", 10),
		std::make_tuple("text \r\n.\r", "\n", 10),
		std::make_tuple("text \r\n", ".\r\n", 10),
		std::make_tuple("text \r\n.", "\r\n", 10),
		std::make_tuple("text \r", "\n.\r\n", 10),
		std::make_tuple("text \r\n.\r", "\n", 10)
		)
);

INSTANTIATE_TEST_SUITE_P(
	InvalidCases,
	FindEndOfMailData,
	::testing::Values(
		std::make_tuple("", "text \r\n.\n", -1),
		std::make_tuple("", "text \r.\r\n", -1),
		std::make_tuple("", "text \n.\r\n", -1),
		std::make_tuple("", "text \n.\n", -1),
		std::make_tuple("", "text \r.\r", -1),
		std::make_tuple("", "text \r\n.\rf\n", -1),
		std::make_tuple("", "text \r\n.\r.\n", -1),
		std::make_tuple("", "text \r\n.text\r\n", 0),
		std::make_tuple("", "text \r\n text \r\n", 0),
		std::make_tuple("", "text \r\n..\r\n", 0),
		std::make_tuple("", "text \r\n...\r\n", 0),
		std::make_tuple("", "text \r\n. \r\n", 0),
		std::make_tuple("", "text \r\n .\r\n", 0),
		std::make_tuple("", "text \r\n,\r\n", 0),
		std::make_tuple("", "text \r\n.", 0),
		std::make_tuple("", "text .\r\n", 0),
		std::make_tuple("", "text \r\n\r\n", 0)
	)
);

class FindEndOfMailData_char_by_char: 
	public ::testing::TestWithParam<std::tuple<std::string,std::string,std::string,std::string,std::string>>
{};

TEST_P(FindEndOfMailData_char_by_char, DetectsEndOfData){
	//Arrange
	MailTransaction tr;
	int result;
	auto tpl = GetParam();
	std::string string1 = std::get<0>(tpl);
	std::string string2 = std::get<1>(tpl);
	std::string string3 = std::get<2>(tpl);
	std::string string4 = std::get<3>(tpl);
	std::string string5 = std::get<4>(tpl);

	//Act
	tr.FindEndOfMailData(string1.c_str(), string1.length());
	tr.FindEndOfMailData(string2.c_str(), string2.length());
	tr.FindEndOfMailData(string3.c_str(), string3.length());
	tr.FindEndOfMailData(string4.c_str(), string4.length());
	result = tr.FindEndOfMailData(string5.c_str(), string5.length());

	//Assert
	ASSERT_EQ(result, string1.length()+string2.length()+string3.length()+string4.length()+string5.length());
}

INSTANTIATE_TEST_SUITE_P(
	ValidString,
	FindEndOfMailData_char_by_char,
	::testing::Values(
		std::make_tuple("\r", "\n", ".", "\r", "\n"),
		std::make_tuple("", "\r\n", ".", "\r", "\n"),
		std::make_tuple("", "", "\r\n.", "\r", "\n")
	)
);


