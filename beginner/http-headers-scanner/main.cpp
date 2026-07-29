#include<bits/stdc++.h>
#include "assessment.h"
#include<fstream>
#include<sstream>
#include<cctype>
using namespace std;

ifstream inFile("http-check.txt");
ofstream outFile("result.txt");

void printReport(const ScanResult& r){
    outFile<<"======================================"<<endl;
    outFile<<"URL: "<<r.url<<endl;
    if(!r.reachable){
        outFile<<" [ERROR] Cannot connect to: "<<r.errorMessage<<endl;
        return;
    }
    outFile<<"HTTP Status : "<<r.httpStatus<<endl;
    outFile<<"Time        : "<<r.totalTimeMs<<endl;

    Assessment a = assess(r);
    double pct = a.maxScore > 0?(100.0 * a.score/a.maxScore):0.0;
    outFile<<"Severity Score: "<<a.score<<"/"<<a.maxScore<<" (" <<pct<<"%) -> Ranked: "<<a.grade<<endl;
    outFile<<"Header Present ("<<a.present.size()<<"):\n";
    for(const auto& h:a.present) outFile<<"  [OK]"<<h<<endl;
    outFile<<"Missing Header (" <<a.missing.size()<<"):\n";
    for(const auto& h:a.missing) outFile<<"  [--]"<<h<<endl;
}

vector<string> loadUrls(const string& path){
    vector<string> urls;
    if(!inFile.is_open()){
        cerr<<"Unable to open file: "<<path<<endl;
        return urls;
    }
    string line;
    while(getline(inFile,line)){
        size_t start = line.find_first_not_of(" \t\r\n");
        size_t end = line.find_last_not_of(" \t\r\n");
        if(start == string::npos) continue;
        line = line.substr(start, end-start+1);
        if(line.empty()||line[0]=='#')continue;
        urls.push_back(line);
    }
    return urls;
}


int main(int argc, char** argv){
    if(argc<2){
        cerr<<"How to use: "<<argv[0]<<" <file_contains_paths_url>\n";
        cerr<<"Sample file urls.txt:\n";
        cerr<<" https://example.com\n https://github.com\n";
        return 1;
    }
    vector<string>urls = loadUrls(argv[1]);
    if(urls.empty()){
        cerr<<"Have no urls to scan.\n";
        return 1;
    }
    curl_global_init(CURL_GLOBAL_DEFAULT);

    vector<ScanResult> results;
    for(const auto& url:urls){
        cout<<"Scanning: "<<url<<"...\n";
        results.push_back(scanUrl(url));
    }

    outFile<<"\n===============DETAILED REPORT================\n";
    for(const auto& r:results){
        printReport(r);
    }

    outFile<<"\n===============SUMMARY REPORT================\n";
    outFile<<"Summary of scanned urls: "<<results.size()<<endl;
    int reachableCount = 0;
    for(const auto& r:results) if (r.reachable) reachableCount++;
    outFile<<"Accessible urls: "<<reachableCount<<"/"<<results.size()<<endl;
    curl_global_cleanup();
    return 0;
}