#ifndef CONTROLFLOW_H
#define CONTROLFLOW_H

#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <vector>
#include <fstream>
#include <ostream>
#include <algorithm>
#include <sstream>
#include <ctime>
#include "Parser.h"

using namespace std;

class ControlFlow
{
public:
	ControlFlow();
	void codeTransform(vector<string> segment, string path, string dest, int source, int desti);

private:
	vector<string> ctrlFlTran(vector<string> segment);
	bool isAssign(string text);
	bool isCondition(string text);
	int findPos(vector<int> seq, int i);
};
#endif