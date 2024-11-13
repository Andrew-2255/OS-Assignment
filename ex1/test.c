#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <assert.h>

bool validate_ip(const char* ip) {
    unsigned int a, b, c, d;
    if (sscanf(ip, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    char reconstructed[16];
    snprintf(reconstructed, sizeof(reconstructed), "%u.%u.%u.%u", a, b, c, d);
    return (strcmp(reconstructed, ip) == 0);
}

// Test function for is_valid_ip
void test_is_valid_ip() {
    // Valid IPs
    assert(validate_ip("0.0.0.0") == true);
    assert(validate_ip("255.255.255.255") == true);
    assert(validate_ip("192.168.1.1") == true);
    assert(validate_ip("1.1.1.1") == true);
    assert(validate_ip("127.0.0.1") == true);
    assert(validate_ip("123.45.67.89") == true);

    // Invalid IPs
    assert(validate_ip("1.1.1") == false);             // Only 3 octets
    assert(validate_ip("1.1.1.1.1") == false);         // 5 octets
    assert(validate_ip("1..1.1") == false);            // Empty octet
    assert(validate_ip("256.1.1.1") == false);         // Octet exceeds 255
    assert(validate_ip("1.1.1.-1") == false);          // Negative octet
    assert(validate_ip("1.1.1.1a") == false);          // Non-digit character
    assert(validate_ip("1.1.1.a") == false);           // Non-digit character in last octet
    assert(validate_ip("1.1.1.1.") == false);          // Trailing dot
    assert(validate_ip(".1.1.1.1") == false);          // Leading dot
    assert(validate_ip("01.1.1.1") == false);          // Leading zero in first octet
    assert(validate_ip("1.01.1.1") == false);          // Leading zero in second octet
    assert(validate_ip("1.1.01.1") == false);          // Leading zero in third octet
    assert(validate_ip("1.1.1.01") == false);          // Leading zero in fourth octet
    assert(validate_ip("1.1.1.1a") == false);          // Extra character
    assert(validate_ip("1.1.1.1 ") == false);          // Trailing space
    assert(validate_ip(" 1.1.1.1") == false);          // Leading space
    assert(validate_ip("") == false);                   // Empty string
    assert(validate_ip(NULL) == false);                 // Null pointer
    assert(validate_ip("1.1.1.1. ") == false);         // Extra characters after valid IP
    assert(validate_ip("1.1.1..1") == false);          // Empty octet between dots
    assert(validate_ip("1.1..1.1") == false);          // Empty octet between dots
    assert(validate_ip("1..1.1.1") == false);          // Empty octet between dots
    assert(validate_ip("300.1.1.1") == false);         // Octet exceeds 255
    assert(validate_ip("1.1.1.1\n") == false);         // Newline character
    assert(validate_ip("1.1.1.1\t") == false);         // Tab character

    printf("All tests passed!\n");
}

int main() {
    test_is_valid_ip();
    return 0;
}