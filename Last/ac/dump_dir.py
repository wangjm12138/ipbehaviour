# -*- coding: utf-8 -*-
import ahocorasick
import pickle
#test = ['\\..\\..\\..\\..\\..\\..\\','/../../../../../../','\\\\..\\\\..\\\\..','/\\..\\..\\..\\..\\','/????/????/????/','/..%5c..%5c..%5c..','/..%5c../','/\\x5c\\x5c../','..\\../../..\\','%5c..%5c..%5c..','%5c..','%5C..%5C..%5C..','%5C..']
test = ['\\..\\..\\..\\..\\..\\..\\','/../../../../../../','\\\\..\\\\..\\\\..','/\\..\\..\\..\\..\\','/????/????/????/','/\\x5c\\x5c../','..\\../../..\\','/..%5c..%5c..%5c..','/..%5C..%5C..%5C..','/..%5c../','/..%5C../','../%5c../%5c../%5c..','../%5C../%5C../%5C..','%5C..%5C..%5C..','%5c..%5c..%5c..','%2f..%2f..%2f..','%2F..%2F..%2F..']
def build_actree(wordlist):
        actree = ahocorasick.Automaton()
        for index, word in enumerate(wordlist):
            actree.add_word(word, (index, word))
        actree.make_automaton()
        return actree
actree_test = build_actree(test)
test_str = '/DVWA-master/%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../%5C../etc/passwd'
for i in actree_test.iter(test_str):
    print (i)

fn = 'dir_traver.pkl'
with open(fn,'bw') as f:
	pickled = pickle.dump(actree_test,f)

