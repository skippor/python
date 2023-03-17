# -*- coding: utf-8 -*-

import sys

def add(a,b):
    return a + b
    
def mul(a,b):
    return a * b

def sub(a,b):
    return a - b

def div(a,b):
    return a / b

def test_cal(a,b):
    print("{} + {} = {}".format(a, b, add(a,b)))
    print("{} - {} = {}".format(a, b, sub(a,b)))
    print("{} * {} = {}".format(a, b, mul(a,b)))
    print("{} / {} = {}".format(a, b, div(a,b)))

if __name__ == "__main__":
    test_cal(1,2)
    test_cal(3,1)
    test_cal(1,0)
    










