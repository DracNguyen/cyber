#ifndef SCANHEADER_H
#define SCANHEADER_H
#include<vector>
#include<string>
#include<curl/curl.h>
#include<map>
#include<algorithm>
using namespace std;
struct ScanResult{
    string url;
    bool reachable = false;
    long httpStatus = 0;
    double totalTimeMs = 0.0;
    map<string,string>headers;
    string errorMessage;
};
static size_t headerCallback (char* buffer, size_t size, size_t nitems, void* userdata){
    size_t totalSize = size * nitems;
    auto* headers = static_cast<map<string,string>*>(userdata);

    string line(buffer,totalSize);
    while(!line.empty() && (line.back() == '\r'|| line.back()=='\n')){
        line.pop_back();
    }

    auto colonPos = line.find(':');
    if(colonPos != string::npos){
        string key = line.substr(0,colonPos);
        string value = line.substr(colonPos +1);
        size_t start = value.find_first_not_of(" \t");
        if(start != string::npos) value = value.substr(start);

        transform(key.begin(),key.end(),key.begin(),[](unsigned char c){return tolower(c);});
        (*headers)[key]=value;
    }
    return totalSize;
}

static size_t discardBody(char* /*ptr*/,size_t size,size_t nmemb, void* /*userdata*/){
    return size*nmemb;
}

ScanResult scanUrl(const string& url){
    ScanResult result;
    result.url = url;

    CURL* curl = curl_easy_init();
    if(!curl){
        result.errorMessage = "Failed to initialize CURL";
        return result;
    }
    char errbuf[CURL_ERROR_SIZE] = {0};
    curl_easy_setopt(curl,CURLOPT_URL,url.c_str());
    curl_easy_setopt(curl,CURLOPT_FOLLOWLOCATION,1L);
    curl_easy_setopt(curl,CURLOPT_MAXREDIRS,5L);
    curl_easy_setopt(curl,CURLOPT_TIMEOUT,10L);
    curl_easy_setopt(curl,CURLOPT_CONNECTTIMEOUT,5L);
    curl_easy_setopt(curl,CURLOPT_NOSIGNAL,1L);
    curl_easy_setopt(curl,CURLOPT_SSL_VERIFYPEER,2L);
    curl_easy_setopt(curl,CURLOPT_SSL_VERIFYHOST,2l);
    curl_easy_setopt(curl,CURLOPT_USERAGENT,"http-seciruty-scanner/1.0");
    curl_easy_setopt(curl,CURLOPT_ERRORBUFFER,errbuf);

    curl_easy_setopt(curl,CURLOPT_HEADERFUNCTION,headerCallback);
    curl_easy_setopt(curl,CURLOPT_HEADERDATA,&result.headers);

    curl_easy_setopt(curl,CURLOPT_WRITEFUNCTION,discardBody);
    curl_easy_setopt(curl,CURLOPT_WRITEDATA, nullptr);

    CURLcode res = curl_easy_perform(curl);

    if(res == CURLE_OK){
        result.reachable =true;
        curl_easy_getinfo(curl,CURLINFO_RESPONSE_CODE,&result.httpStatus);
        curl_easy_getinfo(curl,CURLINFO_TOTAL_TIME,&result.totalTimeMs);
        result.totalTimeMs *= 1000.0;
    }else{
        result.reachable = false;
        result.errorMessage = errbuf[0]? errbuf:curl_easy_strerror(res);
    }
    curl_easy_cleanup(curl);
    return result;
}

#endif