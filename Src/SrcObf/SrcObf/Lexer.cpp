#include "Lexer.h"

using namespace std;

Lexer::TOKENTYPE token_type;
Lexer::KEYWORD_ID key;
Lexer::Lexer()
{
	token_type = NOTHING;
}


vector<string> Lexer::lexical(vector<string> new_expr)
{
	vector<string> kw;
	string temp = "";
	for (int i = 0; i < new_expr.size(); i++)
	{
		temp = new_expr[i];
		getToken(temp);
		if (token_type == KEYWORD)
			kw.push_back(keyword(temp));
		else if (token_type == BRACKET_L)
			kw.push_back("BRACKET_L");
		else if (token_type == IDENTIFIER)
			kw.push_back("IDENTIFIER");
		else if (token_type == NUMBER)
			kw.push_back("NUMBER");
		else if (token_type == OPERATOR)
			kw.push_back(get_op_id(temp));
		else if (token_type == BRACKET_R)
			kw.push_back("BRACKET_R");
		else if (token_type == BRACER_L)
			kw.push_back("BRACER_L");
		else if (token_type == BRACER_R)
			kw.push_back("BRACER_R");
		else if (token_type == FUNCTION_CALL)
			kw.push_back("FUNCTION_CALL");
		else if (token_type == VALUE)
			kw.push_back("VALUE");
		else
			kw.push_back("UNKNOWN");
	}
	return kw;
}

string Lexer::keyword(string keyword)
{
	getKeyword(keyword);
	if (key == IF)
		return "IF";
	else if (key == THEN)
		return "THEN";
	else if (key == ELSE)
		return "ELSE";
	else if (key == GOTO)
		return "GOTO";
	else if (key == CONTINUE)
		return "CONTINUE";
	else if (key == BREAK)
		return "BREAK";
	else if (key == SWITCH)
		return "SWITCH";
	else if (key == CASE)
		return "CASE";
	else if (key == FOR)
		return "FOR";
	else if (key == WHILE)
		return "WHILE";
	else
		return "UNKNOWN";
}

void Lexer::getToken(string expr)
{
	if (expr.compare("if") == 0 
		|| expr.compare("else if") == 0
		|| expr.compare("else") == 0 
		|| expr.compare("goto") == 0
		|| expr.compare("continue") == 0 
		|| expr.compare("break") == 0
		|| expr.compare("switch") == 0 
		|| expr.compare("case") == 0)
		token_type = KEYWORD;
	else if (expr.compare("(") == 0)
		token_type = BRACKET_L;
	else if (isdigit(atoi(expr.c_str())))
		token_type = NUMBER;
	else if (expr.compare("+") == 0
		|| expr.compare("-") == 0
		|| expr.compare("*") == 0
		|| expr.compare("/") == 0
		|| expr.compare("%") == 0
		|| expr.compare("^") == 0
		|| expr.compare("&") == 0
		|| expr.compare("|") == 0
		|| expr.compare(">>") == 0
		|| expr.compare("<<") == 0
		|| expr.compare("||") == 0
		|| expr.compare("&&") == 0
		|| expr.compare("==") == 0
		|| expr.compare("!=") == 0
		|| expr.compare("<") == 0
		|| expr.compare(">") == 0
		|| expr.compare("<=") == 0
		|| expr.compare(">=") == 0)
	token_type = OPERATOR;
	else if (expr.compare(")") == 0)
		token_type = BRACKET_R;
	else if (expr.compare("{") == 0)
		token_type = BRACER_L;
	else if (expr.compare("}") == 0)
		token_type = BRACER_R;
	else if (expr.find("(") != string::npos
		&& expr.find(")") != string::npos)
		token_type = FUNCTION_CALL;
	else if (expr.find("'") != string::npos
		|| expr.find("\"") != string::npos
		|| expr.find("true") != string::npos
		|| expr.find("false") != string::npos
		|| isdigit(atoi((char*)expr.c_str())))
		token_type = VALUE;
	else
		token_type = IDENTIFIER;
}

void Lexer::getKeyword(string keyword)
{
	if (keyword.compare("if") == 0)
		key = IF;
	else if (keyword.compare("else if") == 0)
		key = THEN;
	else if (keyword.compare("else") == 0)
		key = ELSE;
	else if (keyword.compare("goto") == 0)
		key = GOTO;
	else if (keyword.compare("continue") == 0)
		key = CONTINUE;
	else if (keyword.compare("break") == 0)
		key = BREAK;
	else if (keyword.compare("switch") == 0)
		key = SWITCH;
	else if (keyword.compare("case") == 0)
		key = CASE;
	else
		key = OTHER;
}

string Lexer::get_op_id(string op)
{
	if (op.compare("+") == 0)
		return "PLUS";
	else if (op.compare("-") == 0)
		return "MINUS";
	else if (op.compare("*") == 0)
		return "MULTIPLY";
	else if (op.compare("/") == 0)
		return "DIVIDE";
	else if (op.compare("%") == 0)
		return "MODULUS";
	else if (op.compare("^") == 0)
		return "XOR";
	else if (op.compare("&") == 0)
		return "BWAND";
	else if (op.compare("|") == 0)
		return "BWOR";
	else if (op.compare("<<") == 0)
		return "SHIFTL";
	else if (op.compare(">>") == 0)
		return "SHIFTR";
	else if (op.compare("&&") == 0)
		return "AND";
	else if (op.compare("||") == 0)
		return "OR";
	else if (op.compare("==") == 0)
		return "EQUAL";
	else if (op.compare("!=") == 0)
		return "NOTEQ";
	else if (op.compare("<") == 0)
		return "LESSER";
	else if (op.compare(">") == 0)
		return "GREATER";
	else if (op.compare(">=") == 0)
		return "LESSEREQ";
	else if (op.compare("<=") == 0)
		return "GREATEREQ";
	else
		return "NOTOP";
}