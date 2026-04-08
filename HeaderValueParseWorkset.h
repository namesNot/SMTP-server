struct HeaderValueParseWorkset{
	//const char *CRLF = "\r\n";
	/*int pos_in_CRLF = 0, len_CRLF = 2,*/int open_comment_count = 0, result = 0;
	bool has_non_whitespace = false, has_opening_quote = false;

	// показывает какой объект разбирается в данный момент
	bool quoted_pair = false, atom = true, comment = false, quoted_string = false, name_addr = false, group = false;
	//показывает какие объекты были в каждом mailbox
	bool was_comment = false, was_atom = false, was_quoted_string = false, was_name_addr = false;

	bool mailbox_started = false, potentially_invalid_char = false, special_char = false, comma_required = false;
};
