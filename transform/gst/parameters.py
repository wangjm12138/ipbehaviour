import os

class parameters:
    
    """ path """
    
    #    SQL     #
    train_white = 'sql-attack/train_normal.txt'
    train_black = 'sql-attack/train_sql.txt'
    eval_white = 'sql-attack/test_normal.txt'    
    eval_black = 'sql-attack/test_sql.txt'
    #eval_white = 'sql-attack/HttpParamsDataset-master/norm.txt'
    #eval_black = 'sql-attack/HttpParamsDataset-master/sqli.txt'
   

    #save_dir = '/root/webAttackDetection/modelZoo/'
    save_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)),'modelZoo')
	
    #model_dir = '/root/webAttackDetection/modelZoo/classifier.pkl'
    model_dir = os.path.join(save_dir,'classifier.pkl')
 
    """ transform params """
    analyzer = 'word'
    ngram = (1,2)
    max_features = 50
    lowercase = False
    """ tfidf feature map """
    #vocabulary = 'results/results-SQL/filter_vocabulary.pkl' 
    vocabulary = None 
    #key_word = ['base64_decode','base64','eval',  \
    #            'eval(','@eval(','decode','<script','alert(']
    #classifier params#
    n_estimators = 50
    oob_score = False
    verbose = 0
    njob = 8

    
    """ statistic params """

    """ all tfidf statistic  """
    feature_mode = 'tfidf'

    #token_tfidf = r'(?u)\b\w\w+\b|\b\W\w+\b'
    #token_tfidf = r'(?u)\b\w\w+\b'
    token_tfidf = '''
        (?x)[\w\.]+?\(
        |\)
        |"\w+?"
        |'\w+?'
        |http://\w
        |</\w+>
        |<\w+>
        |<\w+
        |\w+=
        |>
        |[\w\.]+
    '''

    """ 0:get_len  1:get_url_count  2:get_evil_char  3:get_evil_word  4:get_last_char 5:get_ entropy """
    feature_usage = [3,4,5]
    
    token_char = "[<>,/]"
    token_word = "(alert)|(onMouseOver)|(expression)|       \
                  (confirm)|(onfocus)|(href)|(script)|      \
                  (cookie)|(script=)(%3c)|(onerror)|        \
                  (onload)|(eval)|(src=)|(prompt)|(http)|(https)"

    #token_word = ['alert(','base64_decode','<script',
    #              'href','onfocus','onMouseOver',
    #              'onload','onerror','eval(','http','https']
    valRate = 0.1

