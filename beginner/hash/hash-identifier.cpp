#include <bits/stdc++.h>
#include "prefix.h"

bool prefix_match(string s){
    size_t pos = s.find("$");
    if(pos == string::npos){
        return 0;
    }
    size_t pos2 = s.find("$", pos+1);
    string prefix = s.substr(pos+1, pos2-pos-1);
    // cout<<prefix<<endl;
    map<string, string>::iterator it = hash_types_prefix.find(prefix);
    if(it != hash_types_prefix.end()){
        cout << it->second << endl;
        return 1;
    }
    return 0;
}

bool special_match(string s){
    size_t pos = s.find("::");
    if(pos != string::npos){
        cout<<"NetNTLM" << endl;
        return 1;
    }
    return 0;
}

int main(){
    cout << "Hash Identifier" << endl;
    cout << "----------------" << endl;
    cout << "Enter the hash to identify: ";
    string s;
    getline(cin,s);
    int n = s.length();
    cout << "Result: ";
    if(prefix_match(s)){
        return 0;
    }
    if(special_match(s)){
        return 0;
    }
    
    switch(n){
        case 32:
            cout << "MD5/NTLM/MD4/RIPEMD128" << endl;
            break;
        case 40:
            cout << "SHA1" << endl;
            break;
        case 64:
            cout << "SHA256" << endl;
            break;
        case 96:
            cout << "SHA384" << endl;
            break;
        case 128:
            cout << "SHA512" << endl;
            break;
        default:
            cout << "Unknown Hash Type" << endl;
    }
}