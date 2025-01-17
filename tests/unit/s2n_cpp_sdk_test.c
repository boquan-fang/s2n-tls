#include <curl/curl.h>
#include <s2n.h>

int main() {
    s2n_init();
    curl_global_init(CURL_GLOBAL_ALL);
    curl_global_cleanup();
    s2n_cleanup();
    s2n_cleanup_final();
    return 0;
}
