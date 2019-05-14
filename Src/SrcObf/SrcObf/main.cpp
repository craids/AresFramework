#include <iostream>
#include "Parser.h"
#include "ControlFlow.h"
#include <vector>

using namespace std;

void main(int argc, char** argv)
{
	string path(argv[1]), dest(argv[2]);
	Parser p = Parser();
	vector<string> lex = p.recursiveParse(path);
	ControlFlow cf = ControlFlow();
	cf.codeTransform(lex, path, dest, p.source, p.dest);
}