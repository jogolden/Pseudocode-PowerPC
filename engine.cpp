// Originally created by Youness Alaoui
// Pseudo code generation by imGol2den
// Example: http://i.gyazo.com/15de806b17ee28315945993e303b4db3.gif

#include "engine.hpp"

#define MASK32_ALLSET 0xFFFFFFFF
#define MASK64_ALLSET 0xFFFFFFFFFFFFFFFFLL
#define BUFFER_SIZE 128
char g_buffer[BUFFER_SIZE];

// Specific instruction buffers
char g_instruction[BUFFER_SIZE];
char g_operand0[BUFFER_SIZE], g_operand1[BUFFER_SIZE], g_operand2[BUFFER_SIZE], g_operand3[BUFFER_SIZE], g_operand4[BUFFER_SIZE];
char g_RA[BUFFER_SIZE], g_RS[BUFFER_SIZE], g_RB[BUFFER_SIZE];
int g_SH, g_MB, g_ME;

// Function parsing buffers
char g_functionName[BUFFER_SIZE], g_functionPrototype[BUFFER_SIZE];
char g_pseudocode[BUFFER_SIZE];

// Comparing struct and buffer
struct cmp_info_t {
	char opperand1[BUFFER_SIZE], opperand2[BUFFER_SIZE];
};
cmp_info_t cmp_info[10]; // I think theres only like 7 conditional registers but what ever lol

// generates the mask between MaskBegin(MB) and MaskEnd(ME) inclusive
// MB and ME should be values 0 - 31
unsigned int GenerateMask32(int MB, int ME)
{
	if(	MB <  0 || ME <  0 ||
		MB > 31 || ME > 31 )
	{
		printf("Error with paramters GenerateMask32(%d, %d)\n", MB, ME);
	 return 0;
	}
	
	unsigned int mask = 0;
	if(MB < ME+1)
	{
		// normal mask
		for(int i=MB; i<=ME; i=i+1)
		{
			mask = mask | (1<<(31-i));
		}
	}
	else if(MB == ME+1)
	{
		// all mask bits set
		mask = MASK32_ALLSET;
	}
	else if(MB > ME+1)
	{
		// split mask
		unsigned int mask_lo = GenerateMask32(0, ME);
		unsigned int mask_hi = GenerateMask32(MB, 31);
		mask = mask_lo | mask_hi;
	}
	
	return mask;
}

// generates the mask between MaskBegin(MB) and MaskEnd(ME) inclusive
// MB and ME should be values 0 - 63
unsigned long long GenerateMask64(int MB, int ME)
{
	if(	MB <  0 || ME <  0 ||
		MB > 63 || ME > 63 )
	{
		printf("Error with paramters GenerateMask64(%d, %d)\n", MB, ME);
	 return 0;
	}
	
	unsigned long long mask = 0;
	if(MB < ME+1)
	{
		// normal mask
		for(int i=MB; i<=ME; i=i+1)
		{
			mask = mask | (unsigned long long)(1LL<<(63-i));
		}
	}
	else if(MB == ME+1)
	{
		// all mask bits set
		mask = MASK64_ALLSET;
	}
	else if(MB > ME+1)
	{
		// split mask
		unsigned long long mask_lo = GenerateMask64(0, ME);
		unsigned long long mask_hi = GenerateMask64(MB, 63);
		mask = mask_lo | mask_hi;
	}
	
	return mask;
}

// generate string showing rotation or shifting within instruction
// returns:	true if string requires brackets if a mask is used, ie: (r4 << 2) & 0xFF
bool GenerateRotate32(char* buff, int buffSize, const char* src, int leftShift, int rightShift, unsigned int& mask)
{
	// work out "rotate" part of the instruction
	if(	leftShift== 0 && rightShift==32 ||
		leftShift==32 && rightShift== 0 )
	{
		sprintf_s(buff, buffSize, "%s", src);
	 return false;
	}
	
	if(((MASK32_ALLSET<<leftShift ) & mask) == 0)
	{
		// right shift only
		if((MASK32_ALLSET>>rightShift) == mask)
			mask = MASK32_ALLSET;
		sprintf_s(buff, buffSize, "%s >> %d", src, rightShift);
	}
	else if(((MASK32_ALLSET>>rightShift) & mask) == 0)
	{
		// left shift only
		if((MASK32_ALLSET<<leftShift) == mask)
			mask = MASK32_ALLSET;
		sprintf_s(buff, buffSize, "%s << %d", src, leftShift);
	}
	else
	{
		// shift both ways
		sprintf_s(buff, buffSize, "(%s << %d) | (%s >> %d)", src, leftShift, src, rightShift);
	}

	return true;
}

// generate string showing rotation or shifting within instruction
// returns:	true if string requires brackets if a mask is used, ie: (r4 << 2) & 0xFF
bool GenerateRotate64(char* buff, int buffSize, const char* src, int leftShift, int rightShift, unsigned long long& mask)
{
	// work out "rotate" part of the instruction
	if(	leftShift== 0 && rightShift==64 ||
		leftShift==64 && rightShift== 0 )
	{
		// no rotation
		sprintf_s(buff, buffSize, "%s", src);
	 return false;
	}
	
	if(((MASK64_ALLSET<<leftShift ) & mask) == 0)
	{
		// right shift only
		if((MASK64_ALLSET>>rightShift) == mask)
			mask = MASK64_ALLSET;
		sprintf_s(buff, buffSize, "%s >> %d", src, rightShift);
	}
	else if(((MASK64_ALLSET>>rightShift) & mask) == 0)
	{
		// left shift only
		if((MASK64_ALLSET<<leftShift) == mask)
			mask = MASK64_ALLSET;
		sprintf_s(buff, buffSize, "%s << %d", src, leftShift);
	}
	else
	{
		// shift both ways
		sprintf_s(buff, buffSize, "(%s << %d) | (%s >> %d)", src, leftShift, src, rightShift);
	}
	
	return true;
}

// register rotate and immediate mask
bool Rotate_iMask32(char* buff, int buffSize, const char* leftRotate, int mb, int me)
{
	// calculate the mask
	// if no mask, then result is always 0
	unsigned int mask = GenerateMask32(mb, me);
	if(mask == 0)
	{
		// no rotation
		sprintf_s(buff, buffSize, "%s = 0;", g_RA);
	 return true;
	}
	
	// work out "rotate" part of the instruction
	// if all mask bits are set, then no need to use the mask
	char rot_str[BUFFER_SIZE];
	sprintf_s(rot_str, sizeof(rot_str), "(%s << %s) | (%s >> 32-%s)", g_RS, leftRotate, g_RS, leftRotate);
	if(mask == MASK32_ALLSET)
	{
		//sprintf_s(buff, buffSize, "%s = (u32)(%s)", g_RA, rot_str);
		sprintf_s(buff, buffSize, "%s = %s;", g_RA, rot_str);
	 return true;
	}
	
	// generate mask string
	char mask_str[BUFFER_SIZE];
	sprintf_s(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", mask);
	
	// generate the resultant string
	sprintf_s(buff, buffSize, "%s = (%s) & %s;", g_RA, rot_str, mask_str);
	return true;
}

// immediate rotate and immediate mask
bool iRotate_iMask32(char* buff, int buffSize, int leftRotate, int mb, int me)
{
	// calculate the mask
	// if no mask, then result is always 0
	unsigned int mask = GenerateMask32(mb, me);
	if(mask == 0)
	{
		sprintf_s(buff, buffSize, "%s = 0;", g_RA);
	 return true;
	}
	
	// work out "rotate" part of the instruction
	// if all mask bits are set, then no need to use the mask
	char rot_str[BUFFER_SIZE];
	bool brackets = GenerateRotate32(rot_str, sizeof(rot_str), g_RS, leftRotate, 32-leftRotate, mask);
	if(mask == MASK32_ALLSET)
	{
//		if(brackets)
//			sprintf_s(buff, buffSize, "%s = (u32)(%s)", g_RA, rot_str);
//		else
//			sprintf_s(buff, buffSize, "%s = (u32)%s", g_RA, rot_str);
		sprintf_s(buff, buffSize, "%s = %s;", g_RA, rot_str);
		return true;
	}
	
//	MASK32_ALLSET << leftRotate
	
	// generate mask string
	char mask_str[BUFFER_SIZE];
	sprintf_s(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", mask);
	
	// generate the resultant string
	if(brackets)
		sprintf_s(buff, buffSize, "%s = (%s) & %s;", g_RA, rot_str, mask_str);
	else
		sprintf_s(buff, buffSize, "%s = %s & %s;", g_RA, rot_str, mask_str);
	return true;
}

// insert immediate rotate and immediate mask
bool insert_iRotate_iMask32(char* buff, int buffSize, int leftRotate, int mb, int me)
{
	// calculate the mask
	// if no mask, then result is always 0
	unsigned int mask = GenerateMask32(mb, me);
	if(mask == 0)
	{
		sprintf_s(buff, buffSize, "%s = %s;", g_RA, g_RA);
		return true;
	}
	
	// work out "rotate" part of the instruction
	// if all mask bits are set, then no need to use the mask
	char rot_str[BUFFER_SIZE];
	bool brackets = GenerateRotate32(rot_str, sizeof(rot_str), g_RS, leftRotate, 32-leftRotate, mask);
	if(mask == MASK32_ALLSET)
	{
		sprintf_s(buff, buffSize, "%s = %s;", g_RA, rot_str);
		return true;
	}
	
	// generate mask strings
	char mask_str[BUFFER_SIZE];
	sprintf_s(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", mask);
	unsigned int not_mask = ~mask;
	char not_mask_str[BUFFER_SIZE];
	sprintf_s(not_mask_str, sizeof(not_mask_str), "%s%X", (not_mask<0xA)?"":"0x", not_mask);
	
	// generate the resultant string
	if(brackets)
		sprintf_s(buff, buffSize, "%s = (%s & ~%s) | ((%s) & %s);", g_RA,
					g_RA, mask_str,
					rot_str, mask_str);
	else
		sprintf_s(buff, buffSize, "%s = (%s & ~%s) | (%s & %s);", g_RA,
					g_RA, mask_str,
					rot_str, mask_str);
	return true;
}

// register rotate and immediate mask
bool Rotate_iMask64(char* buff, int buffSize, const char* leftRotate, int mb, int me)
{
	// calculate the mask
	// if no mask, then result is always 0
	unsigned long long mask = GenerateMask64(mb, me);
	if(mask == 0)
	{
		sprintf_s(buff, buffSize, "%s = 0;", g_RA);
		return true;
	}
	
	// work out "rotate" part of the instruction
	// if all mask bits are set, then no need to use the mask
	char rot_str[BUFFER_SIZE];
	sprintf_s(rot_str, sizeof(rot_str), "(%s << %s) | (%s >> 64-%s)", g_RS, leftRotate, g_RS, leftRotate);
	if(mask == MASK64_ALLSET)
	{
		sprintf_s(buff, buffSize, "%s = %s;", g_RA, rot_str);
		return true;
	}
	
	// generate mask string
	char mask_str[BUFFER_SIZE];
	if(mask>>32 == 0)
		sprintf_s(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", (unsigned long)mask);
	else
		sprintf_s(mask_str, sizeof(mask_str), "%s%X%08X", (mask<0xA)?"":"0x", (unsigned long)(mask>>32), (unsigned long)mask);
	
	// generate the resultant string
	sprintf_s(buff, buffSize, "%s = (%s) & %s;", g_RA, rot_str, mask_str);
	return true;
}

// immediate rotate and immediate mask
bool iRotate_iMask64(char* buff, int buffSize, int leftRotate, int mb, int me)
{
	// calculate the mask
	// if no mask, then result is always 0
	unsigned long long mask = GenerateMask64(mb, me);
	if(mask == 0)
	{
		sprintf_s(buff, buffSize, "%s = 0;", g_RA);
		return true;
	}
	
	// work out "rotate" part of the instruction
	// if all mask bits are set, then no need to use the mask
	char rot_str[BUFFER_SIZE];
	bool brackets = GenerateRotate64(rot_str, sizeof(rot_str), g_RS, leftRotate, 64-leftRotate, mask);
	if(mask == MASK64_ALLSET)
	{
		sprintf_s(buff, buffSize, "%s = %s;", g_RA, rot_str);
		return true;
	}
	
	// generate mask string
	char mask_str[BUFFER_SIZE];
	if(mask>>32 == 0)
		sprintf_s(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", (unsigned long)mask);
	else
		sprintf_s(mask_str, sizeof(mask_str), "%s%X%08X", (mask<0xA)?"":"0x", (unsigned long)(mask>>32), (unsigned long)mask);
	
	// generate the resultant string
	if(brackets)
		sprintf_s(buff, buffSize, "%s = (%s) & %s;", g_RA, rot_str, mask_str);
	else
		sprintf_s(buff, buffSize, "%s = %s & %s;", g_RA, rot_str, mask_str);
	return true;
}

// insert immediate rotate and immediate mask
bool insert_iRotate_iMask64(char* buff, int buffSize, int leftRotate, int mb, int me)
{
	// calculate the mask
	// if no mask, then result is always 0
	unsigned long long mask = GenerateMask64(mb, me);
	if(mask == 0)
	{
		sprintf_s(buff, buffSize, "%s = 0;", g_RA);
		return true;
	}
	
	// work out "rotate" part of the instruction
	// if all mask bits are set, then no need to use the mask
	char rot_str[BUFFER_SIZE];
	bool brackets = GenerateRotate64(rot_str, sizeof(rot_str), g_RS, leftRotate, 64-leftRotate, mask);
	if(mask == MASK64_ALLSET)
	{
		sprintf_s(buff, buffSize, "%s = %s;", g_RA, rot_str);
		return true;
	}
	
	// generate mask string
	char mask_str[BUFFER_SIZE];
	if(mask>>32 == 0)
		sprintf_s(mask_str, sizeof(mask_str), "%s%X", (mask<0xA)?"":"0x", (unsigned long)mask);
	else
		sprintf_s(mask_str, sizeof(mask_str), "%s%X%08X", (mask<0xA)?"":"0x", (unsigned long)(mask>>32), (unsigned long)mask);
	unsigned long long not_mask = ~mask;
	char not_mask_str[BUFFER_SIZE];
	if(not_mask>>32 == 0)
		sprintf_s(not_mask_str, sizeof(not_mask_str), "%s%X", (not_mask<0xA)?"":"0x", (unsigned long)not_mask);
	else
		sprintf_s(not_mask_str, sizeof(not_mask_str), "%s%X%08X", (not_mask<0xA)?"":"0x", (unsigned long)(not_mask>>32), (unsigned long)not_mask);
	
	// generate the resultant string
	if(brackets)
		sprintf_s(buff, buffSize, "%s = (%s & ~%s) | ((%s) & %s);", g_RA,
					g_RA, mask_str,
					rot_str, mask_str);
	else
		sprintf_s(buff, buffSize, "%s = (%s & ~%s) | (%s & %s);", g_RA,
					g_RA, mask_str,
					rot_str, mask_str);
	return true;
}

int parse_instruction(ea_t ea, strvec_t *sv) {

	#pragma region Instruction
	ua_mnem(ea, g_instruction, BUFFER_SIZE);
	tag_remove(g_instruction, g_instruction, BUFFER_SIZE);
	ua_ana0(ea);
	if(cmd.itype == 13 && (cmd.auxpref & 8)) {
		qstrncpy(g_instruction, "bl", BUFFER_SIZE);
	} else if(cmd.itype == 320 && cmd.auxpref == 0x500) {
		qstrncpy(g_instruction, "blr", BUFFER_SIZE);
	}
	char *ptr = (char*)qstrstr(g_instruction, ".");
	if(ptr) {
		*ptr = 0;
	}
	#pragma endregion
	
	#pragma region Instruction operands
	ua_outop2(ea, g_operand0, BUFFER_SIZE, 0);
	tag_remove(g_operand0, g_operand0, BUFFER_SIZE);
	ptr = (char*)qstrstr(g_operand0, "#");
	if(ptr) {
		*(ptr - 1) = 0;
		*ptr = 0;
	}
	ua_outop2(ea, g_operand1, BUFFER_SIZE, 1);
	tag_remove(g_operand1, g_operand1, BUFFER_SIZE);
	ptr = (char*)qstrstr(g_operand1, "#");
	if(ptr) {
		*(ptr - 1) = 0;
		*ptr = 0;
	}
	ua_outop2(ea, g_operand2, BUFFER_SIZE, 2);
	ptr = (char*)qstrstr(g_operand2, "#");
	if(ptr) {
		*(ptr - 1) = 0;
		*ptr = 0;
	}
	tag_remove(g_operand2, g_operand2, BUFFER_SIZE);
	const char *comma1 = qstrstr(g_operand2, ",");
	if(comma1 != NULL) {
		qstrncpy(g_operand3, comma1 + 1, BUFFER_SIZE);
		g_operand2[comma1 - g_operand2] = 0;
		const char *comma2 = qstrstr(comma1 + 1, ",");
		if(comma2 != NULL) {
			qstrncpy(g_operand4, comma2 + 1, BUFFER_SIZE);
			g_operand3[comma2 - (comma1 + 1)] = 0;
		}
	}
	ptr = (char*)qstrstr(g_operand3, "#");
	if(ptr) {
		*(ptr - 1) = 0;
		*ptr = 0;
	}
	ptr = (char*)qstrstr(g_operand4, "#");
	if(ptr) {
		*(ptr - 1) = 0;
		*ptr = 0;
	}
	#pragma endregion

	#pragma region Labels
	get_name(ea, ea, g_buffer, BUFFER_SIZE);
	if(strcmp(g_functionName, g_buffer) && *g_buffer != NULL) {
		qstrncat(g_buffer, ":", BUFFER_SIZE);
		sv->push_back(simpleline_t(g_buffer));
	}
	#pragma endregion

	#pragma region add | addi
	if(!qstrcmp(g_instruction, "add") || !qstrcmp(g_instruction, "addi")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s += %s;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s + %s;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion
	
	#pragma region addis
	else if(!qstrcmp(g_instruction, "addis")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s += %s << 16;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = (%s + %s) << 16;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region and | andi
	else if(!qstrcmp(g_instruction, "and") || !qstrcmp(g_instruction, "andi")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s &= %s;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s & %s;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region andis
	else if(!qstrcmp(g_instruction, "andis")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s &= %s << 16;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = (%s & %s) << 16;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region b
	else if(!qstrcmp(g_instruction, "b")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "goto %s;", g_operand0);
	}
	#pragma endregion

	#pragma region bdnz
	else if(!qstrcmp(g_instruction, "bdnz")) {
		sv->push_back(simpleline_t("CTR--;")); // lol
		qsnprintf(g_pseudocode, BUFFER_SIZE, "goto %s;", g_operand1);
	}
	#pragma endregion

	#pragma region beq
	else if(!qstrcmp(g_instruction, "beq")) {
		int cr = atol(g_operand0 + 2);
		if(!qstrcmp(g_operand1, "lr")) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s == %s) { return; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s == %s) { goto %s; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2, g_operand1);
		}
	}
	#pragma endregion

	#pragma region bge
	else if(!qstrcmp(g_instruction, "bge")) {
		int cr = atol(g_operand0 + 2);
		if(!qstrcmp(g_operand1, "lr")) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s >= %s) { return; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s >= %s) { goto %s; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2, g_operand1);
		}
	}
	#pragma endregion

	#pragma region bgt
	else if(!qstrcmp(g_instruction, "bgt")) {
		int cr = atol(g_operand0 + 2);
		if(!qstrcmp(g_operand1, "lr")) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s > %s) { return; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s > %s) { goto %s; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2, g_operand1);
		}
	}
	#pragma endregion

	#pragma region bl
	else if(!qstrcmp(g_instruction, "bl")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s(...);", g_operand0);
	}
	#pragma endregion

	#pragma region blr
	else if(!qstrcmp(g_instruction, "blr")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "return;", g_operand0);
	}
	#pragma endregion

	#pragma region ble
	else if(!qstrcmp(g_instruction, "ble")) {
		int cr = atol(g_operand0 + 2);
		if(!qstrcmp(g_operand1, "lr")) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s <= %s) { return; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s <= %s) { goto %s; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2, g_operand1);
		}
	}
	#pragma endregion

	#pragma region blt
	else if(!qstrcmp(g_instruction, "blt")) {
		int cr = atol(g_operand0 + 2);
		if(!qstrcmp(g_operand1, "lr")) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s < %s) { return; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s < %s) { goto %s; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2, g_operand1);
		}
	}
	#pragma endregion

	#pragma region bne
	else if(!qstrcmp(g_instruction, "bne")) {
		int cr = atol(g_operand0 + 2);
		if(!qstrcmp(g_operand1, "lr")) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s != %s) { return; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "if(%s != %s) { goto %s; }", cmp_info[cr].opperand1, cmp_info[cr].opperand2, g_operand1);
		}
	}
	#pragma endregion

	#pragma region cmpd | cmpdi | cmpld | cmpldi | cmpw | cmpwi | cmplw | cmplwi
	else if(!qstrcmp(g_instruction, "cmpd") || !qstrcmp(g_instruction, "cmpdi") || !qstrcmp(g_instruction, "cmpld") || !qstrcmp(g_instruction, "cmpldi") || !qstrcmp(g_instruction, "cmpw") || !qstrcmp(g_instruction, "cmpwi") || !qstrcmp(g_instruction, "cmplw") || !qstrcmp(g_instruction, "cmplwi")) {
		if(!strncmp(g_operand0, "cr", 2)) {
			int cr = atol(g_operand0 + 2);
			qstrncpy(cmp_info[cr].opperand1, g_operand1, BUFFER_SIZE);
			qstrncpy(cmp_info[cr].opperand2, g_operand2, BUFFER_SIZE);
			return 1;
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "// unsupported %s (no cr)", g_instruction);
		}
	}
	#pragma endregion

	#pragma region divw | divwu
	else if(!qstrcmp(g_instruction, "divw") || !qstrcmp(g_instruction, "divwu")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s /= %s;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s / %s;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region eqv
	else if(!qstrcmp(g_instruction, "eqv")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s ^= %s; // warning: possibly wrong", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s ^ %s; // warning: possibly wrong", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region lbz | lbzu
	else if(!qstrcmp(g_instruction, "lbz") || !qstrcmp(g_instruction, "lbzu")) {
		int fp = qstrlen(g_operand1) - qstrlen(qstrstr(g_operand1, "("));
		qstrncpy(g_buffer, g_operand1 + fp + 1, BUFFER_SIZE);
		g_buffer[qstrlen(g_buffer) - 1] = 0;
		g_operand1[fp] = 0;
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = *(uint8_t*)(%s + %s);", g_operand0, g_buffer, g_operand1);
	}
	#pragma endregion

	#pragma region lbzx
	else if(!qstrcmp(g_instruction, "lbzx")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = *(uint8_t*)(%s + %s);", g_operand0, g_operand1, g_operand2);
	}
	#pragma endregion

	#pragma region ld | ldu
	else if(!qstrcmp(g_instruction, "ld") || !qstrcmp(g_instruction, "ldu")) {
		int fp = qstrlen(g_operand1) - qstrlen(qstrstr(g_operand1, "("));
		qstrncpy(g_buffer, g_operand1 + fp + 1, BUFFER_SIZE);
		g_buffer[qstrlen(g_buffer) - 1] = 0;
		g_operand1[fp] = 0;
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = *(uint64_t*)(%s + %s);", g_operand0, g_buffer, g_operand1);
	}
	#pragma endregion

	#pragma region ldx
	else if(!qstrcmp(g_instruction, "ldx")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = *(uint64_t*)(%s + %s);", g_operand0, g_operand1, g_operand2);
	}
	#pragma endregion

	#pragma region lhz | lhzu
	else if(!qstrcmp(g_instruction, "lhz") || !qstrcmp(g_instruction, "lhzu")) {
		int fp = qstrlen(g_operand1) - qstrlen(qstrstr(g_operand1, "("));
		qstrncpy(g_buffer, g_operand1 + fp + 1, BUFFER_SIZE);
		g_buffer[qstrlen(g_buffer) - 1] = 0;
		g_operand1[fp] = 0;
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = *(uint16_t*)(%s + %s);", g_operand0, g_buffer, g_operand1);
	}
	#pragma endregion

	#pragma region lhzx
	else if(!qstrcmp(g_instruction, "lhzx")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = *(uint16_t*)(%s + %s);", g_operand0, g_operand1, g_operand2);
	}
	#pragma endregion

	#pragma region li
	else if(!qstrcmp(g_instruction, "li")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s;", g_operand0, g_operand1);
	}
	#pragma endregion

	#pragma region lis
	else if(!qstrcmp(g_instruction, "lis")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s << 16;", g_operand0, g_operand1);
	}
	#pragma endregion

	#pragma region lwz | lwzu
	else if(!qstrcmp(g_instruction, "lwz") || !qstrcmp(g_instruction, "lwzu")) {
		int fp = qstrlen(g_operand1) - qstrlen(qstrstr(g_operand1, "("));
		qstrncpy(g_buffer, g_operand1 + fp + 1, BUFFER_SIZE);
		g_buffer[qstrlen(g_buffer) - 1] = 0;
		g_operand1[fp] = 0;
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = *(uint32_t*)(%s + %s);", g_operand0, g_buffer, g_operand1);
	}
	#pragma endregion

	#pragma region lwzx
	else if(!qstrcmp(g_instruction, "lwzx")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = *(uint32_t*)(%s + %s);", g_operand0, g_operand1, g_operand2);
	}
	#pragma endregion

	#pragma region mtctr
	else if(!qstrcmp(g_instruction, "mtctr")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "CTR = %s;", g_operand1);
	}
	#pragma endregion

	#pragma region mflr
	else if(!qstrcmp(g_instruction, "mflr")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = LR;", g_operand0);
	}
	#pragma endregion

	#pragma region mtlr
	else if(!qstrcmp(g_instruction, "mtlr")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "LR = %s;", g_operand1);
	}
	#pragma endregion

	#pragma region mfspr | mtspr
	else if(!qstrcmp(g_instruction, "mfspr") || !qstrcmp(g_instruction, "mtspr")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s; // spr", g_operand0, g_operand1);
	}
	#pragma endregion

	#pragma region mr
	else if(!qstrcmp(g_instruction, "mr")) {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s;", g_operand0, g_operand1);
	}
	#pragma endregion

	#pragma region mulld | mulli | mullw
	else if(!qstrcmp(g_instruction, "mulld") || !qstrcmp(g_instruction, "mulli") || !qstrcmp(g_instruction, "mullw")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s *= %s;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s * %s;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region or | ori
	else if(!qstrcmp(g_instruction, "or") || !qstrcmp(g_instruction, "ori")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s |= %s;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s | %s;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region oris
	else if(!qstrcmp(g_instruction, "oris")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s |= %s << 16;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = (%s | %s) << 16;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region sld | sldi | slw | slwi
	else if(!qstrcmp(g_instruction, "sld") || !qstrcmp(g_instruction, "sldi") || !qstrcmp(g_instruction, "slw") || !qstrcmp(g_instruction, "slwi")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s <<= %s;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s << %s;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region srd | srdi | srw | srwi
	else if(!qstrcmp(g_instruction, "srd") || !qstrcmp(g_instruction, "srdi") || !qstrcmp(g_instruction, "srw") || !qstrcmp(g_instruction, "srwi")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s >>= %s;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s >> %s;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region stb | stbu
	else if(!qstrcmp(g_instruction, "stb") || !qstrcmp(g_instruction, "stbu")) {
		int fp = qstrlen(g_operand1) - qstrlen(qstrstr(g_operand1, "("));
		qstrncpy(g_buffer, g_operand1 + fp + 1, BUFFER_SIZE);
		g_buffer[qstrlen(g_buffer) - 1] = 0;
		g_operand1[fp] = 0;
		qsnprintf(g_pseudocode, BUFFER_SIZE, "*(uint8_t*)(%s + %s) = %s;", g_buffer, g_operand1, g_operand0);
	}
	#pragma endregion

	#pragma region std | stdu
	else if(!qstrcmp(g_instruction, "std") || !qstrcmp(g_instruction, "stdu")) {
		int fp = qstrlen(g_operand1) - qstrlen(qstrstr(g_operand1, "("));
		qstrncpy(g_buffer, g_operand1 + fp + 1, BUFFER_SIZE);
		g_buffer[qstrlen(g_buffer) - 1] = 0;
		g_operand1[fp] = 0;
		qsnprintf(g_pseudocode, BUFFER_SIZE, "*(uint64_t*)(%s + %s) = %s;", g_buffer, g_operand1, g_operand0);
	}
	#pragma endregion

	#pragma region sth | sthu
	else if(!qstrcmp(g_instruction, "sth") || !qstrcmp(g_instruction, "sthu")) {
		int fp = qstrlen(g_operand1) - qstrlen(qstrstr(g_operand1, "("));
		qstrncpy(g_buffer, g_operand1 + fp + 1, BUFFER_SIZE);
		g_buffer[qstrlen(g_buffer) - 1] = 0;
		g_operand1[fp] = 0;
		qsnprintf(g_pseudocode, BUFFER_SIZE, "*(uint16_t*)(%s + %s) = %s;", g_buffer, g_operand1, g_operand0);
	}
	#pragma endregion

	#pragma region stw | stwu
	else if(!qstrcmp(g_instruction, "stw") || !qstrcmp(g_instruction, "stwu")) {
		int fp = qstrlen(g_operand1) - qstrlen(qstrstr(g_operand1, "("));
		qstrncpy(g_buffer, g_operand1 + fp + 1, BUFFER_SIZE);
		g_buffer[qstrlen(g_buffer) - 1] = 0;
		g_operand1[fp] = 0;
		qsnprintf(g_pseudocode, BUFFER_SIZE, "*(uint32_t*)(%s + %s) = %s;", g_buffer, g_operand1, g_operand0);
	}
	#pragma endregion

	#pragma region subf | subfic | subi
	else if(!qstrcmp(g_instruction, "subf") || !qstrcmp(g_instruction, "subfic") || !qstrcmp(g_instruction, "subi")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s -= %s;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s - %s;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region xor | xori
	else if(!qstrcmp(g_instruction, "xor") || !qstrcmp(g_instruction, "xori")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s ^= %s;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = %s ^ %s;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region xoris
	else if(!qstrcmp(g_instruction, "xoris")) {
		if(!qstrcmp(g_operand0, g_operand1)) {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s ^= %s << 16;", g_operand0, g_operand2);
		} else {
			qsnprintf(g_pseudocode, BUFFER_SIZE, "%s = (%s ^ %s) << 16;", g_operand0, g_operand1, g_operand2);
		}
	}
	#pragma endregion

	#pragma region clrlwi
	else if(!qstrcmp(g_instruction, "clrlwi")) {
		// Clear left immediate
		// clrlwi RA, RS, n
		// (rlwinm RA, RS, 0, n, 31)
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		int n = atol(g_operand2);
		g_SH = 0;
		g_MB = n;
		g_ME = 31;
	
		iRotate_iMask32(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region clrrwi
	else if(!qstrcmp(g_instruction, "clrrwi")) {
		// Clear right immediate
		// clrrwi RA, RS, n
		// (rlwinm RA, RS, 0, 0, 31-n)
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		int n = atol(g_operand2);
		g_SH = 0;
		g_MB = 0;
		g_ME = 31 - n;

		iRotate_iMask32(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region clrslwi
	else if(!qstrcmp(g_instruction, "clrslwi")) {
		// Clear left and shift left immediate
		// clrslwi RA, RS, b, n
		// (rlwinm RA, RS, b-n, 31-n)
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		int b = atol(g_operand2);
		int n = atol(g_operand3);
		g_SH = n;
		g_MB = 31;
		g_ME = 31 - b;
	
		iRotate_iMask32(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region extrwi
	else if(!qstrcmp(g_instruction, "extrwi")) {
		// Extract and right justify immediate
		// extrwi RA, RS, n, b
		// rlwinm RA, RS, b+n, 32-n, 31
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		int n = atol(g_operand2);
		int b = atol(g_operand3);
		g_SH = 32 - (b + n);
		g_MB = 32 - n;
		g_ME = 31;

		iRotate_iMask32(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region extlwi
	else if(!qstrcmp(g_instruction, "extlwi")) {
		// Extract and left justify immediate
		// extlwi RA, RS, n, b
		// rlwinm RA, RS, b, 0, n-1
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		int n = atol(g_operand2);
		int b = atol(g_operand3);
		g_SH = b;
		g_MB = 0;
		g_ME = n - 1;

		iRotate_iMask32(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region inslwi
	else if(!qstrcmp(g_instruction, "inslwi")) {
		// Insert from left immediate
		// inslwi RA, RS, n, b
		// rlwimi RA, RS, 32-b, b, (b+n)-1
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		int n = atol(g_operand2);
		int b = atol(g_operand3);
		g_SH = 32 - b;
		g_MB = b;
		g_ME = b + n - 1;

		insert_iRotate_iMask32(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region insrwi
	else if(!qstrcmp(g_instruction, "insrwi")) {
		// Insert from right immediate
		// insrwi RA, RS, n, b
		// rlwimi RA, RS, 32-(b+n), b, (b+n)-1
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		int n = atol(g_operand2);
		int b = atol(g_operand3);
		g_SH = 32 - (b + n);
		g_MB = b;
		g_ME = b + n - 1;

		insert_iRotate_iMask32(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rlwinm
	else if(!qstrcmp(g_instruction, "rlwinm")) {
		// Rotate Left Word Immediate Then AND with Mask
		// rlwinm RA, RS, SH, MB, ME
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = atol(g_operand3);
		g_ME = atol(g_operand4);

		iRotate_iMask32(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rlwnm
	else if(!qstrcmp(g_instruction, "rlwnm")) {
		// Rotate Left Word Then AND with Mask
		// rlwnm RA, RS, RB, MB, ME
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		qstrncpy(g_RB, g_operand2, sizeof(g_RB));
		g_MB = atol(g_operand3);
		g_ME = atol(g_operand4);

		Rotate_iMask32(g_pseudocode, BUFFER_SIZE, g_RB, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rotlwi
	else if(!qstrcmp(g_instruction, "rotlwi")) {
		// Rotate left immediate
		// rotlwi RA, RS, n
		// rlwinm RA, RS, n, 0, 31
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		int n = atol(g_operand2);
		g_SH = n;
		g_MB = 0;
		g_ME = 31;

		iRotate_iMask32(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rotrwi
	else if(!qstrcmp(g_instruction, "rotrwi")) {
		// Rotate right immediate
		// rotrwi RA, RS, n
		// rlwinm RA, RS, 32-n, 0, 31
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		int n = atol(g_operand2);
		g_SH = 32 - n;
		g_MB = 0;
		g_ME = 31;

		iRotate_iMask32(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rotlw
	else if(!qstrcmp(g_instruction, "rotlw")) {
		// Rotate left
		// rotlw RA, RS, RB
		// rlwnm RA, RS, RB, 0, 31
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		qstrncpy(g_RB, g_operand2, sizeof(g_RB));
		g_MB = 0;
		g_ME = 31;

		Rotate_iMask32(g_pseudocode, BUFFER_SIZE, g_RB, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rldcr
	else if(!qstrcmp(g_instruction, "rldcr")) {
		// Rotate Left Double Word then Clear Right
		// rldcr RA, RS, RB, ME
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		qstrncpy(g_RB, g_operand2, sizeof(g_RB));
		g_MB = 0;
		g_ME = atol(g_operand3);

		Rotate_iMask64(g_pseudocode, BUFFER_SIZE, g_RB, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rldic
	else if(!qstrcmp(g_instruction, "rldic")) {
		// Rotate Left Double Word Immediate then Clear
		// rldic RA, RS, SH, MB
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = atol(g_operand3);
		g_ME = 63 - g_SH;

		iRotate_iMask64(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rldicl
	else if(!qstrcmp(g_instruction, "rldicl")) {
		// Rotate Left Double Word Immediate then Clear Left
		// rldicl RA, RS, SH, MB
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = atol(g_operand3);
		g_ME = 63;

		iRotate_iMask64(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rldicr
	else if(!qstrcmp(g_instruction, "rldicr")) {
		// Rotate Left Double Word Immediate then Clear Right
		// rldicr RA, RS, SH, ME
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = 0;
		g_ME = atol(g_operand3);

		iRotate_iMask64(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rldimi
	else if(!qstrcmp(g_instruction, "rldimi")) {
		// Rotate Left Double Word Immediate then Mask Insert
		// rldimi RA, RS, SH, MB
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = atol(g_operand3);
		g_ME = 63 - g_SH;

		insert_iRotate_iMask64(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rlwimi
	else if(!qstrcmp(g_instruction, "rlwimi")) {
		// Rotate Left Word Immediate Then Mask Insert
		// rlwimi RA, RS, SH, MB, ME
		qstrncpy(g_RA, g_operand0, sizeof(g_RA));
		qstrncpy(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = atol(g_operand3);
		g_ME = atol(g_operand4);

		insert_iRotate_iMask64(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region extrdi
	else if(!qstrcmp(g_instruction, "extrdi")) {
		// Extract double word and right justify immediate
		// extrdi RA, RS, SH, MB
		strncpy_s(g_RA, g_operand0, sizeof(g_RA));
		strncpy_s(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = atol(g_operand3);
		g_ME = 63;

		iRotate_iMask64(g_pseudocode, BUFFER_SIZE, g_SH + g_MB, 64 - g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rotldi
	else if(!qstrcmp(g_instruction, "rotldi")) {
		// Rotate double word left immediate
		// rotldi RA, RS, SH
		strncpy_s(g_RA, g_operand0, sizeof(g_RA));
		strncpy_s(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = 0;//atol(g_operand3);
		g_ME = 63;

		iRotate_iMask64(g_pseudocode, BUFFER_SIZE, g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region rotrdi
	else if(!qstrcmp(g_instruction, "rotrdi")) {
		// Rotate double word right immediate
		// rotrdi RA, RS, SH
		strncpy_s(g_RA, g_operand0, sizeof(g_RA));
		strncpy_s(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = 0;//atol(g_operand3);
		g_ME = 63;

		iRotate_iMask64(g_pseudocode, BUFFER_SIZE, 64 - g_SH, g_MB, g_ME);
	}
	#pragma endregion

	#pragma region clrldi
	else if(!qstrcmp(g_instruction, "clrldi")) {
		// Clear left double word immediate
		// clrldi RA, RS, SH
		strncpy_s(g_RA, g_operand0, sizeof(g_RA));
		strncpy_s(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = atol(g_operand3);
		g_ME = 63;

		iRotate_iMask64(g_pseudocode, BUFFER_SIZE, 0/*g_SH*/, g_SH/*g_MB*/, g_ME);
	}
	#pragma endregion

	#pragma region extldi
	else if(!qstrcmp(g_instruction, "extldi")) {
		// Extract double word and left justify immediate
		// extldi RA, RS, SH, ME
		// rldicr RA, RS, ME, SH - 1
		strncpy_s(g_RA, g_operand0, sizeof(g_RA));
		strncpy_s(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = 0;
		g_ME = atol(g_operand3);

		iRotate_iMask64(g_pseudocode, BUFFER_SIZE, g_ME, g_MB, g_SH - 1);
	}
	#pragma endregion

	#pragma region clrrdi
	else if(!qstrcmp(g_instruction, "clrrdi")) {
		// Clear right double word immediate
		// clrrdi RA, RS, SH
		strncpy_s(g_RA, g_operand0, sizeof(g_RA));
		strncpy_s(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = 0;
		g_ME = atol(g_operand3);

		iRotate_iMask64(g_pseudocode, BUFFER_SIZE, 0/*g_SH*/, 63 - g_SH/*g_MB*/, g_ME);
	}
	#pragma endregion

	#pragma region clrlsldi
	else if(!qstrcmp(g_instruction, "clrlsldi")) {
		// Clear left double word and shift left immediate
		// clrlsldi RA, RS, SH, MB
		strncpy_s(g_RA, g_operand0, sizeof(g_RA));
		strncpy_s(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = atol(g_operand3);
		g_ME = 63 - g_SH;

		iRotate_iMask64(g_pseudocode, BUFFER_SIZE, g_SH, g_MB - g_SH, g_ME);
	}
	#pragma endregion

	#pragma region insrdi
	else if(!qstrcmp(g_instruction, "insrdi")) {
		// Insert double word from right immediate
		// insrdi RA, RS, SH, MB
		strncpy_s(g_RA, g_operand0, sizeof(g_RA));
		strncpy_s(g_RS, g_operand1, sizeof(g_RS));
		g_SH = atol(g_operand2);
		g_MB = atol(g_operand3);
		g_ME = 63 - g_SH;

		insert_iRotate_iMask64(g_pseudocode, BUFFER_SIZE, 64 - (g_MB + g_SH), g_MB, g_ME);
	}
	#pragma endregion

	#pragma region unsupported
	else {
		qsnprintf(g_pseudocode, BUFFER_SIZE, "// unsupported: %s", g_instruction);
	}
	#pragma endregion
	
	// Add the instruction
	sv->push_back(simpleline_t(g_pseudocode));

	return 1;
}

int parse_function(ea_t ea, strvec_t *sv) {
	func_t *func = get_func(ea);
	if(func == NULL) {
		return 0;
	}

	get_func_name(func->startEA, g_functionName, BUFFER_SIZE);
	qsnprintf(g_functionPrototype, BUFFER_SIZE, "%s(...)", g_functionName);
	//sv->push_back(simpleline_t("// I think I messed up a little on (addis, lis, oris, etc)"));
	sv->push_back(simpleline_t(g_functionPrototype));
	sv->push_back(simpleline_t("{"));

	for(ea_t i = func->startEA; i < func->endEA; i += 4) {
		if(!parse_instruction(i, sv)) {
			sv->clear();
			sv->push_back(simpleline_t("fatal error in 'parse_instruction'"));
			return 0;
		}
	}
	
	// If the last line is 'goto %s' then do 'return %s(...)'
	if(!strncmp(sv->operator[](sv->size() - 1).line.c_str(), "goto", 4)) {
		sv->operator[](sv->size() - 1).line.replace("goto", "return");
		sv->operator[](sv->size() - 1).line.replace(";", "(...);");
	}

	// If the last line is 'return' then do remove it
	//if(!strncmp(sv->operator[](sv->size() - 1).line.c_str(), "return;", 7)) {
		//sv->pop_back();
	//}

	sv->push_back(simpleline_t("}"));

	return 1;
}

int parse_current_function(strvec_t *sv) {
	return parse_function(get_screen_ea(), sv);
}