# CTFd-yarachallenge

This plugin allows you to create challenges that give players points by awards for each right yara match to a md5 file. It also also you to set wrong answers in which they will lose points for matching the wrong files. 


#Setup
Note: You must have the multianswer plugin installed 


    git pull https://github.com/wroersma/CTFd-multi-answer /path-to-CTFd/CTFd/plugins/multianswer/
    Clone yara-challenge  into the dir /CTFd/plugins/


#Edit config
```    
vim /path-to-CTFd/CTFd/plugins/multianswer/__init__.py
comment out the last line
#app.view_functions['challenges.chal'] = chal
 
```

#Questions

If you have any questions please contact Wyatt Roersma(wyattroersma@wyattroersma.com)