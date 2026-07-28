#ifndef HEADERCHECK_H
#define HEADERCHECK_H
#include<vector>
#include<string>
using namespace std;

struct HeaderCheck{
    string name;
    string displayName;
    string description;
    int weight;
};

static const vector<HeaderCheck> SECURITY_HEADERS = {
    {"strict-transport-security","Strict-Transport-Security (HSTS)","This header enforces secure (HTTP over SSL/TLS) connections to the server.",30},
    {"content-security-policy","Content-Security-Policy (CSP)","This header helps prevent cross-site scripting (XSS), clickjacking, and other code injection attacks.",30},
    {"x-content-type-options","X-Content-Type-Options","This header prevents browsers from interpreting files as a different MIME type than what is specified in the Content-Type header.",15},
    {"x-frame-options","X-Frame-Options","This header protects against clickjacking attacks by controlling whether a page can be displayed in a frame or iframe.",15},
    {"x-xss-protection","X-XSS-Protection","This header enables the cross-site scripting (XSS) filter built into most modern web browsers.",15},
    {"referrer-policy","Referrer-Policy","This header controls how much referrer information should be included with requests made from your site.",5},
    {"permissions-policy","Permissions-Policy","This header allows you to control which features and APIs can be used in the browser.",5},
    {"cross-origin-opener-policy","Cross-Origin-Opener-Policy (COOP)","This header helps isolate your browsing context from other origins, improving security.",5}
};
#endif