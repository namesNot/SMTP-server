enum AddressKind {GROUP = 0, NAME_ADDR, ADDR_SPEC};

struct HeaderValueInfo{
	enum AddressKind *kinds = NULL;
	int *start_pos = NULL;
	int address_count = 0, address_max_size = 0;
};


