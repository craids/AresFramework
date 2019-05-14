#include "ControlFlow.h"

using namespace std;

ControlFlow::ControlFlow()
{

}

void ControlFlow::codeTransform(vector<string> seg, string path_in, string path_out, int source, int dest)
{
	vector<string> tempStore;
	string temp;
	//int source = 14;
	//int dest = 22;
	int count = 0;
	vector<string> tran = ctrlFlTran(seg);
	ifstream infile;
	ofstream outfile;
	
	infile.open(path_in);
	while (!infile.eof())
	{
		getline(infile, temp);
		if (count == (source - 1))
		{
			tempStore.push_back("{");
			for (int i = 0; i < tran.size(); i++)
				tempStore.push_back(tran[i]);
		}
		else if (count == (dest - 1))
			tempStore.push_back("}");
		else if (count < source || count >= dest)
			tempStore.push_back(temp);
		count++;
	}
	infile.close();

	outfile.open(path_out);
	for (int i = 0; i < tempStore.size(); i++)
		outfile << tempStore[i] << endl;
	outfile.close();
}

vector<string> ControlFlow::ctrlFlTran(vector<string> seg)
{
	vector<string> tran, temp;
	stringstream str, condStr;
	string start = "\twhile (swVar != 0)\n\t{\n\t\tswitch (swVar)\n\t\t{";
	string end = "\t\t}\n\t}";
	int count = 1;
	bool valid = false;
	tran.push_back("\tint swVar = 1;");
	for (int i = 0; i < seg.size(); i++)
	{
		string cond, body, loop;
		stringstream t;
		if (seg[i].find("\tint") != string::npos ||
			seg[i].find("\tbool") != string::npos ||
			seg[i].find("\tchar") != string::npos ||
			seg[i].find("\tstring") != string::npos)
		{
			tran.push_back(seg[i]);
			if (seg[i+1].find("\tint") == string::npos ||
			seg[i+1].find("\tbool") == string::npos ||
			seg[i+1].find("\tchar") == string::npos ||
			seg[i+1].find("\tstring") == string::npos)
				tran.push_back(start);
		}
		else if (seg[i].find("\twhile") != string::npos ||
			seg[i].find("\tfor") != string::npos)
		{
			cond = seg[i].substr(seg[i].find("("), seg[i].find(")") - seg[i].find("(") + 1);
			if (i+1==seg.size() || seg[i+1].find("\twhile") == string::npos &&
				seg[i+1].find("\tfor") == string::npos)
				t << "\t\t\tcase " << count << ":\n\t\t\t\tif " << cond << "\n\t\t\t\t\tswVar = " << (count+1) << ";\n\t\t\t\telse\n\t\t\t\t\tswVar = 0;\n\t\t\t\tbreak;";
			else
				t << "\t\t\tcase " << count << ":\n\t\t\t\tif " << cond << "\n\t\t\t\t\tswVar = " << (count+1) << ";\n\t\t\t\telse\n\t\t\t\t\tswVar = " << (count+2) << ";\n\t\t\t\tbreak;";
			tran.push_back(t.str());
			count++;
			body = seg[i].substr(seg[i].find("{")+1, seg[i].find("}") - (seg[i].find("{")+1));
			while (body.find("\n") != string::npos)
			{
				loop += "\t\t" + body.substr(0, body.find("\n")) + "\n";
				body = body.substr(body.find("\n")+1,body.length() - (body.find("\n")+1)); 
			}
			t.str(string());
			t << "\t\t\tcase " << count << ":" << loop << "\t\t\t\tswVar = " << (count-1) << ";\n\t\t\t\tbreak;";
			tran.push_back(t.str());
			count++;
		}
		else
		{
			if (seg[i].find_first_not_of('\t') != string::npos &&
				seg[i].find_first_not_of(' ') != string::npos)
			{
				t << "\t\t\tcase " << count << ":\n\t\t\t" << seg[i] << "\n\t\t\t\tswVar = " << (count+1) << ";\n\t\t\t\tbreak;";
				tran.push_back(t.str());
				count++;
			}
		}
	}
	tran.push_back(end);
	return tran;
}

bool ControlFlow::isAssign(string text)
{
	bool valid = false;
	string temp = "";
	for (int i = 0; i < text.length(); i++)
	{
		if (text[i] != ' ')
			temp += text[i];
		else if (temp.compare("") != 0)
		{
			if (temp.compare("int") == 0
				|| temp.compare("bool") == 0
				|| temp.compare("char") == 0
				|| temp.compare("string") == 0)
			{
				if (text.find("=") != string::npos
					&& text.find("==") == string::npos)
					valid = true;
			}
			break;
		}
	}
	return valid;
}

bool ControlFlow::isCondition(string text)
{
	bool valid = false;
	string temp = "";
	for (int i = 0; i < text.length(); i++)
	{
		if (text[i] != ' ')
			temp += text[i];
		else if (temp.compare("") != 0)
		{
			if (temp.find("if(") != string::npos
				|| temp.find("if (") == string::npos)
				valid = true;
		}
	}
	return valid;
}

int ControlFlow::findPos(vector<int> seq, int i)
{
	int val = 0;

	for (int j = 0; j < seq.size(); j++)
	{
		if (seq[j] == i)
		{
			val = j + 1;
			break;
		}
	}
	return val;
}