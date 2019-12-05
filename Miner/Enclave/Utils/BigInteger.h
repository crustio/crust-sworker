#ifndef _CRUST_BIGINTEGER_H_
#define _CRUST_BIGINTEGER_H_

#include <vector>
#include <iostream>
#include <cstring>
#include <iomanip>
#include <string>
#include <algorithm>
#include <limits.h>

class BigInteger
{
private:
    static const int BASE = 100000000;
    static const int WIDTH = 8;
    bool sign;
    size_t length;

    void cutLeadingZero();
    void setLength();

public:
    std::vector<int> num;
    BigInteger(int n = 0);
    BigInteger(long long n);
    BigInteger(const char *n);
    BigInteger(const BigInteger &n);

    const BigInteger &operator=(int n);
    const BigInteger &operator=(long long n);
    const BigInteger &operator=(const char *n);
    const BigInteger &operator=(const BigInteger &n);

    size_t size() const;
    BigInteger e(size_t n) const;
    BigInteger abs() const;

    const BigInteger &operator+() const;
    friend BigInteger operator+(const BigInteger &a, const BigInteger &b);
    const BigInteger &operator+=(const BigInteger &n);
    const BigInteger &operator++();
    BigInteger operator++(int);

    BigInteger operator-() const;
    friend BigInteger operator-(const BigInteger &a, const BigInteger &b);
    const BigInteger &operator-=(const BigInteger &n);
    const BigInteger &operator--();
    BigInteger operator--(int);

    friend BigInteger operator*(const BigInteger &a, const BigInteger &b);
    const BigInteger &operator*=(const BigInteger &n);

    friend BigInteger operator/(const BigInteger &a, const BigInteger &b);
    const BigInteger &operator/=(const BigInteger &n);

    friend BigInteger operator%(const BigInteger &a, const BigInteger &b);
    const BigInteger &operator%=(const BigInteger &n);

    friend bool operator<(const BigInteger &a, const BigInteger &b);
    friend bool operator<=(const BigInteger &a, const BigInteger &b);
    friend bool operator>(const BigInteger &a, const BigInteger &b);
    friend bool operator>=(const BigInteger &a, const BigInteger &b);
    friend bool operator==(const BigInteger &a, const BigInteger &b);
    friend bool operator!=(const BigInteger &a, const BigInteger &b);

    friend bool operator||(const BigInteger &a, const BigInteger &b);
    friend bool operator&&(const BigInteger &a, const BigInteger &b);
    bool operator!();
};

#endif // BIGINTEGER_H_