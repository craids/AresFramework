#ifndef PARSER_H
#define PARSER_H

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <fstream>
#include "Lexer.h"
//debug
#include <iostream>

using namespace std;

class Parser
{

public:
	int source, dest;
	Parser();
	vector<string> recursiveParse(string path);
	vector<string> parse(string text);
private:
	vector<string> getExpr(string text);
	bool isMain(string text);
	int isBracer(string text);
};

#endif