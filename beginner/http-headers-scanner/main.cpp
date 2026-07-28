#include<bits/stdc++.h>
#include "headercheck.h"
#include<curl/curl.h>
using namespace std;

ifstream inFile("http-check.txt");
ofstream outFile("result.txt");



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
            
            outFile << "----------------" << endl;
        }
        inFile.close(); // Close the file stream
        outFile.close(); // Close the file stream
    } else {
        cerr << "Error opening file for reading!\n";
    }
    cout << "HTTP Scanneris running... Don't shutdown or exit!" << endl;
}