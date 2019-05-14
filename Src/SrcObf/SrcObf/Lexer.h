#ifndef LEXER_H
#define LEXER_H

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <vector>

using namespace std;

class Lexer
{
public:
	enum TOKENTYPE {NOTHING, KEYWORD, BRACKET_R, IDENTIFIER, 
		NUMBER, OPERATOR, BRACKET_L, FUNCTION_CALL, VALUE,
		BRACER_R, BRACER_L, UNKNOWN};

	enum OPERATOR_ID {BWAND, BWOR, SHIFTL, SHIFTR, AND, OR,
		EQUAL, NOTEQ, LESSER, GREATER, LESSEREQ, GREATEREQ, 
		PLUS, MINUS, MULTIPLY, DIVIDE, MODULUS, XOR, NOTOP};

	enum KEYWORD_ID {IF, THEN, ELSE, GOTO, CONTINUE, BREAK, 
		SWITCH, CASE, OTHER, FOR, WHILE};

public:
	Lexer();
	vector<string> lexical(vector<string> expr);

private:
	string keyword(string keyword);
	void getToken(string t);
	void getKeyword(string k);
	string get_op_id(string op_name);
};

#endif