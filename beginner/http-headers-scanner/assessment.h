#ifndef ASSESSMENT_H
#define ASSESSMENT_H
#include "scanheader.h"
#include "headercheck.h"
using namespace std;

struct Assessment{
    int score = 0;
    int maxScore = 0;
    char grade ='F';
    vector<string>missing;
    vector<string>present;
};

Assessment assess(const ScanResult& r){
    Assessment a;
    for(const auto& check : SECURITY_HEADERS){
        a.maxScore += check.weight;
        if(r.headers.count(check.name)){
            a.score += check.weight;
            a.present.push_back(check.displayName);
        }else{
            a.missing.push_back(check.displayName);
        }
    }
    double pct = a.maxScore > 0?(100.0 * a.score /a.maxScore):0.0;
    if(pct >= 90) a.grade = 'A';
    else if (pct >= 80) a.grade = 'B';
    else if (pct >= 70) a.grade = 'C';
    else if (pct >= 60) a.grade = 'D';
    else a.grade = 'F';
    return a;
}

#endif