#include <bits/stdc++.h>
#include "prefix.h"
ifstream inFile("hash-code.txt");
ofstream outFile("result.txt");

bool prefix_match(string s){
    size_t pos = s.find("$");
    if(pos == string::npos){
        return 0;
    }
    size_t pos2 = s.find("$", pos+1);
    string prefix = s.substr(pos+1, pos2-pos-1);
    map<string, string>::iterator it = hash_types_prefix.find(prefix);
    if(it != hash_types_prefix.end()){
        outFile << it->second << endl;
        return 1;
    }
    return 0;
}

bool special_match(string s){
    size_t pos = s.find("::");
    if(pos != string::npos){
        outFile<<"NetNTLM" << endl;
        return 1;
    }
    return 0;
}

int main(){
    string line;
    
    if (inFile.is_open()) {
        while (getline(inFile, line)) {
            if (outFile.is_open()) {
                outFile << line << "\n";
                outFile << "Result: ";
            } else {
                cerr << "Error opening file for writing!\n";
            }
            int n = line.length();
            if(prefix_match(line)){
                outFile << "----------------" << endl;
                continue;
            }
            if(special_match(line)){
                outFile << "----------------" << endl;
                continue;
            }
            
            switch(n){
                case 32:
                outFile << "MD5/NTLM/MD4/RIPEMD128" << endl;
                break;
                case 40:
                outFile << "SHA1" << endl;
                break;
                case 64:
                outFile << "SHA256" << endl;
                break;
                case 96:
                outFile << "SHA384" << endl;
                break;
                case 128:
                outFile << "SHA512" << endl;
                break;
                default:
                outFile << "Unknown Hash Type" << endl;
            }
            outFile << "----------------" << endl;
        }
        inFile.close(); // Close the file stream

        outFile.close(); // Close the file stream
    } else {
        cerr << "Error opening file for reading!\n";
    }
    cout << "Hash Identifier is running... Don't shutdown or exit!" << endl;
    // cout << "----------------" << endl;
    // cout << "Enter the hash to identify: ";
    // string s;
    // getline(cin,s);
}