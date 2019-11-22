# -*- coding: utf-8 -*-
import os
import six
import time
import configparser
import logging
from logging.handlers import RotatingFileHandler

class TypeWithDefault(type):
	def __init__(cls, *args,**kwargs):
		super(TypeWithDefault, cls).__init__(*args,**kwargs)
		cls._default = None

	def __call__(cls,*args,**kwargs):
		if cls._default is None:
			cls._default = type.__call__(cls,*args,**kwargs)
		return cls._default


class Configuration(six.with_metaclass(TypeWithDefault, object)):
	def __init__(self,configfile=None):
		"""Constructor"""
		self.noconf = False
		if configfile == None:
			curpath = os.path.dirname(os.path.realpath(__file__))
			cfgpath = os.path.join(curpath, "ipbehaviour.ini")
			cfgpath = os.getenv("ipbehaviour_config", cfgpath)
			self.configfile = cfgpath
		else:
			self.configfile = configfile
		if os.path.exists(self.configfile):
			print("Use configfile %s"%(self.configfile))
		else:
			self.noconf = True
			print("Use configfile %s,but isn't exist"%(self.configfile))
		if self.noconf == False:
			conf = configparser.ConfigParser()
			conf.read(self.configfile, encoding="utf-8")
			self.logFile = conf.get("base","logpath")
			self.logmaxBytes = conf.get("base","logmaxBytes")
			self.logbackupCount = conf.get("base","logbackupCount")
			self.logrotatestarted = conf.get("base","logrotatestarted")
			self.url = conf.get("o2test","url")
			self.certId = conf.get("o2test","certId")
			self.certKey = conf.get("o2test","certKey")

"自定义logger对象，继承自logging.Logger，实现文件和控制台的输出"

class MyLogger(object):
		# 首先重建一个logger对象

	def __init__(self, name="logger", level=logging.DEBUG, console_level=logging.INFO, mode='a',config=None):
		self.logger = logging.getLogger(name)
		#防止同一个实例加载好几次的handler
		if len(self.logger.handlers) > 0:
			return None
		# 设置logger的等级
		#super().__init__(name)
		# 注意这各会设置最低的等级，后续的设置只能比这个高
		self.logger.setLevel(level)
		# 组织一个带时间戳的字符串作为日志文件的名字,实现每天记录一个日志文件
		date_time = time.strftime("%Y%m%d", time.localtime(time.time()))
		if config == None or config.noconf:
			log_path_str = os.path.join(os.path.abspath(os.path.join(os.getcwd(), "")), "ipbehaviour")
			logmaxBytes = 256*1024*1024
			logbackupCount = 4
			logrotatestarted = 1
		else:
			log_path_str = config.logFile
			logmaxBytes = config.logmaxBytes
			logbackupCount = config.logbackupCount
			logrotatestarted = config.logrotatestarted

		# python 在创建filehandler时路径不存在会报FileNotFoundError，这里要新建下路径（而具体文件存不存在都时可以的，python会自动创建文件）
		if not os.path.exists(log_path_str):
			os.makedirs(log_path_str)

		logFile = os.path.join(log_path_str, date_time + '.log')
		# 创建一个logging输出到文件的handler并设置等级和输出格式
		# mode属性用于控制写文件的模式，w模式每次程序运行都会覆盖之前的logger，而默认的是a则每次在文件末尾追加

		print(logFile)
		formatter = logging.Formatter('%(asctime)-.19s %(levelname)-.1s %(name)-5.5s %(funcName)-15.15s "%(message)s"')
		fh = RotatingFileHandler(logFile, 'a', maxBytes=int(logmaxBytes) , backupCount=int(logbackupCount))
		#fh = logging.FileHandler(logFile, mode)

		if logrotatestarted == 1:
			fh.doRollover()
		fh.setLevel(level)
		fh.setFormatter(formatter)
		self.logger.addHandler(fh)
		self.logger.w_filehandler = fh

		# 控制台句柄
		ch = logging.StreamHandler()
		ch.setFormatter(formatter)
		ch.setLevel(console_level)
		self.logger.addHandler(ch)
		self.logger.w_consolehandle = ch

	def getLogger(self):
		return self.logger

	def setLevel(self, level):
		self.logger.level = level

	def disable_file(self):
		handlers = self.logger.handlers
		if len(handlers) > 0 and self.logger.w_filehandler in handlers:
			self.logger.removeHandler(self.logger.w_filehandler)
		else:
			print("log file is already disable")

	def enable_file(self):
		handlers = self.logger.handlers
		if len(handlers) > 0 and self.logger.w_filehandler not in handlers:
			self.logger.removeHandler(self.logger.w_filehandler)
		else:
			print("log file is already ensable")

	def disable_console(self):
		handlers = self.logger.handlers
		if len(handlers) > 0 and self.logger.w_consolehandle in handlers:
			self.logger.removeHandler(self.logger.w_consolehandle)
		else:
			print("console is already disable")

	def enable_console(self):
		handlers = self.logger.handlers
		if len(handlers) > 0 and self.logger.w_consolehandle not in handlers:
			self.logger.removeHandler(self.logger.w_consolehandle)
		else:
			print("console is already enable")


#config=Configuration()
#LOGGER  = MyLogger("test",config=config).getLogger()
#LOGGER.disable_file()
#LOGGER.info("hello world!")
