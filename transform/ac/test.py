# -*- coding: utf-8 -*-
import ahocorasick
import pickle
test = ['baidu.com']
def build_actree(wordlist):
        actree = ahocorasick.Automaton()
        for index, word in enumerate(wordlist):
            actree.add_word(word, (index, word))
        actree.make_automaton()
        return actree
actree_test = build_actree(test)
test_str = 'http://baidu.com:443'
for i in actree_test.iter(test_str):
    print (i)

#fn = 'dir_traver.pkl'
#with open(fn,'bw') as f:
#	pickled = pickle.dump(actree_test,f)

