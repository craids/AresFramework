#include "Parser.h"

using namespace std;

Lexer lx;
Parser::Parser()
{
	lx = Lexer();
}

vector<string> Parser::recursiveParse(string path)
{
	vector<string> main;
	vector<string> temp;
	string STMT, tempStmt;
	ifstream infile;
	bool valid, valid2 = false, start = false, isCmplx = false;
	int close = 0, source, dest, count = 1, tempClose = 0;
	infile.open(path);
	while (!infile.eof())
	{
		getline(infile, STMT);
		valid = isMain(STMT);
		if (valid)
		{
			valid2 = valid;
			start = true;
		}
		if (valid2)
		{
			close += isBracer(STMT);
			if (start)
			{
				if (close > 0)
				{
					start = false;
					Parser::source = count;
				}
			}
			else
			{
				if (close != 0)
				{
					
					if (!isCmplx)
					{
						if (STMT.find("while") != string::npos ||
							STMT.find("for") != string::npos ||
							STMT.find("if") != string::npos ||
							STMT.find("else") != string::npos ||
							STMT.find("switch") != string::npos)
						{
							tempStmt += STMT + "\n";
							if (STMT.find("{") != string::npos)
								tempClose++;
							else if (STMT.find("}") != string::npos)
							tempClose--;
							isCmplx = !isCmplx;
						}
						else
							main.push_back(STMT);
					}
					else
					{
						if (STMT.find("{") != string::npos)
							tempClose++;
						else if (STMT.find("}") != string::npos)
							tempClose--;
						tempStmt += STMT + "\n";
						if (tempClose == 0)
						{
							isCmplx = !isCmplx;
							main.push_back(tempStmt);
							tempStmt = "";
						}
					}
				}
				else
				{
					valid2 = false;
					Parser::dest = count;
				}
			}
		}
		count++;
	}
	infile.close();
	return main;
}

vector<string> Parser::parse(string text)
{
	vector<string> temp = getExpr(text);
	return temp;
}

vector<string> Parser::getExpr(string text)
{
	int kwclose = 0;
	vector<string> expr;
	string temp = "", keyword = "";
	char c = '\0';
	for (int i = 0; i < text.length(); i++)
	{
		c = text[i];
		if (c != ' ' && c != '{' && c != '}' && c != '\n' && c != '\t') // 32 = ' ' , 123 = '{' , 125 = '}'
		{

			if (c != '(' && c != ')') // 40 = '(' , 41 = ')'
				temp += c;
			else
			{
				if (keyword.compare("if") != 0 &&
					keyword.compare("else if") != 0 &&
					keyword.compare("switch") != 0 &&
					keyword.compare("while") != 0 &&
					keyword.compare("for") != 0)
				{
					if (c == '(')
					{
						temp += c;
						kwclose++;
					}
					else if (c == ')' && kwclose == 1)
					{
						temp += c;
						kwclose--;
					}
					else
					{
						expr.push_back(temp);cout<<temp<<endl;
						temp = c;
					}
				}
				else
				{
					temp = c;
					expr.push_back(temp);
					keyword = temp;
					temp = "";
				}
			}
		}
		else if (c != 32 && c != '\n' && c != '\t') // { or }
		{
			temp = c;
			expr.push_back(temp);
			keyword = temp;
			temp = "";
		}
		else if (c == ';' && c != '\n' && c != '\t')
		{
			temp += c;
			expr.push_back(temp);
			keyword = temp = "";
		}
		else // spaces, newline, other white-space characters
		{
			if (temp.compare("") != 0
				|| temp.compare("\n") == 0
				|| temp.compare("\t") == 0)
			{
				expr.push_back(temp);
				keyword = temp;
				temp = "";
			}
		}
	}
	return lx.lexical(expr);
}

bool Parser::isMain(string text)
{
	bool valid = false;
	string temp = "";
	for (int i = 0; i < text.length(); i++)
	{
		if (text[i] != ' ')
			temp += text[i];
		else
		{
			if (temp.substr(0,4).compare("main") == 0)
			{
				valid = true;
				break;
			}
			else
				temp = "";
		}
	}
	return valid;
}

int Parser::isBracer(string text)
{
	int result = 0;
	char c;
	for (int i = 0; i < text.length(); i++)
	{
		c = text[i];
		if (c == '{')
			result += 1;
		else if (c == '}')
			result -= 1;
	}
	return result;
}