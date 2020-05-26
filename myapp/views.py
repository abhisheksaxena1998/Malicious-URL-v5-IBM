#!/usr/bin/python
# -*- coding: utf-8 -*-
def warn(*args, **kwargs):
    pass

from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.db.models import Q
from .models import *


# Create your views here.

def error_404_view(request, exception):
    return render(request,'404.html')

def index(request):
    try:
        return render(request, 'index.html')
    except:
        return render(request, '404.html')


def getuserfeedbackform(request):
    try:
        return render(request, 'userfeedbackform.html')
    except:
        return render(request, '404.html')


def saveuserfeedbackform(request):
    try:
        obj = UserFeedBack()
        obj.title = request.GET['usertitle']
        obj.description = request.GET['userdescription']
        obj.save()
        mydict = {'feedback': True}
        return render(request, 'userfeedbackform.html', context=mydict)
    except:
        return render(request, '404.html')

import warnings
warnings.warn = warn
import warnings
import joblib
from lxml import html
from json import dump, loads
from requests import get
import json
from re import sub
from dateutil import parser as dateparser
from time import sleep
from django.http import HttpResponse
from django.shortcuts import render
import os
import pickle
import socket
import geocoder
import whois
import datetime


def result(request):
    text=request.GET['url'].lower()
    try:
        #nm=request.GET['url']
        import tldextract
        do=tldextract.extract(text).domain
        sdo=tldextract.extract(text).subdomain
        suf=tldextract.extract(text).suffix
        
        if not text.startswith('http://') and not text.startswith('https://'):
            return render(request,"404.html")
        if text.startswith('https://malicious-url-detectorv5.herokuapp.com/') or text.startswith('https://mudv9.eu-gb.cf.appdomain.cloud/')  :
            return render(request,'result.html',{'result':'Real-time analysis successfull','f2':'Legtimate','mal': True,'text':text,'name':"The Legions",
                        'org':"The Legions",
                        'add':"New Delhi",
                        'city':"New Delhi",
                        'state':"New Delhi",
                        'ziip':"201301",
                        'country':"India",'emails':"thelegions@gmail.com",
                        'dom':"Hidden For Privacy",'rank':"Hidden For Privacy","tags":"Hidden For Privacy","registrar":"Hidden For Privacy","var13":"NA","varab":"NA","var11":"NA","var10":"NA","var5":"NA","var4":"NA","var3":"NA"})

        elif text.startswith('https://www.youtube.com/results?'):
                        return render(request,'result.html',{'result':'Real-time analysis successfull','f2':'Legtimate','mal': True,'text':text,'name':"NA for youtube search results",
                                'org':"NA for youtube search results",
                                'add':"NA for youtube search results",
                                'city':"NA for youtube search results",
                                'state':"NA for youtube search results",
                                'ziip':"NA for youtube search results",
                                'country':"NA for youtube search results",'emails':"NA for youtube search results",
                                'dom':"NA for youtube search results",'rank':"NA for youtube search results","tags":"NA for youtube search results","registrar":"NA for youtube search results","var13":"NA for youtube search results","varab":"NA for youtube search results","var11":"NA for youtube search results","var10":"NA for youtube search results","var5":"NA for youtube search results","var4":"NA for youtube search results","var3":"NA for youtube search results"})


        elif text.startswith('https://www.google.com/search?q='):
                return render(request,'result.html',{'result':'Real-time analysis successfull','f2':'Legtimate','mal': True,'text':text,'name':"NA for google search",
                        'org':"NA for google search",
                        'add':"NA for google search",
                        'city':"NA for google search",
                        'state':"NA for google search",
                        'ziip':"NA for google search",
                        'country':"NA for google search",'emails':"NA for google search",
                        'dom':"NA for google search",'rank':"NA for google search","tags":"NA for google search","registrar":"Hidden For Privacy","var13":"NA for google search","varab":"NA for google search","var11":"NA for google search","var10":"NA for google search","var5":"NA for google search","var4":"NA for google search","var3":"NA for google search"})


        elif text.startswith('https://www.youtube.com/watch?v='):
            return render(request,'result.html',{'result':'Real-time analysis successfull','f2':'Legtimate','mal': True,'text':text,'name':"NA for Youtube search",
                        'org':"NA for Youtube search",
                        'add':"NA for Youtube search",
                        'city':"NA for Youtube search",
                        'state':"NA for Youtube search",
                        'ziip':"NA for Youtube search",
                        'country':"NA for Youtube search",'emails':"NA for Youtube search",
                        'dom':"NA for Youtube search",'rank':"NA for Youtube search","tags":"NA for Youtube search","registrar":"Hidden For Privacy","var13":"NA for Youtube search","varab":"NA for Youtube search","var11":"NA for Youtube search","var10":"NA for Youtube search","var5":"NA for Youtube search","var4":"NA for Youtube search","var3":"NA for Youtube search"})

        elif (text.startswith('https://www.google.com/search?q=')==False ):

            if text.startswith('https://') or text.startswith('http://'):
                var13="Not Applicable"
                varab="Not Applicable"
                var11="Not Applicable"
                var10="Not Applicable"
                var5="Not Applicable"
                var4="Not Applicable"
                var3="Not Applicable"

                if len(text)<=9:
                    return render(request,'errorpage.html')
                aburl=-1
                digits="0123456789"
                if text[8] in digits:
                    oneval=-1
                else:
                    oneval=1    
                if len(text)>170:
                    secval=-1
                else:
                    secval=1  
                if "@" in text:
                    thirdval=-1
                    var3="'@' detected"
                else:
                    thirdval=1       
                    var3="No '@' detected"
                k=text.count("//")          
                if k>1:
                    fourthval=-1
                    var4="More Redirects"
                else:
                    fourthval=1
                    
                if "-" in do or "-" in sdo:
                    fifthval=-1
                    var5="Prefix-Suffix detected"
                else:
                    fifthval=1 
                    var5="No Prefix-Suffix detected"     

                if "https" in text:
                    sixthval=1
                else:
                    sixthval=-1
                temp=text
                temp=temp[6:]
                k1=temp.count("https")

                if k1 >=1:
                    seventhval=-1
                else:
                    seventhval=1
                if "about:blank" in text:
                    eighthval=-1
                else:
                    eighthval=1
                if "mail()" or "mailto:" in text:
                    ninthval=-1
                else:
                    ninthval=1
                re=text.count("//")          
                if re>3:
                    tenthval=-1
                    var10="redirects more than 2"
                else:
                    tenthval=1    
                    var10=f"{re-1} redirects detected"

                import whois
                from datetime import datetime

                url=text
                #code replaced whois
                # 
                """try:"""
                d=-1
                try:
                    res=whois.whois(url)
                    cpyres=res
                except:
                    print("getaddrerrror DNE")
                    d=0
                    name="Not found in WHOIS database"
                    org="Not found in WHOIS database"
                    add="Not found in WHOIS database"
                    city="Not found in WHOIS database"
                    state="Not found in WHOIS database"
                    ziip="Not found in WHOIS database"
                    country="Not found in WHOIS database"
                    emails="Not found in WHOIS database"
                    dom="Not Found in WHOIS database"
                    registrar="Not Found in WHOIS database"
                if d!=0:    
                    try:
                        if len(res.creation_date)>1:
                            a=res['creation_date'][0]
                            b=datetime.now()
                            c=b-a
                            d=c.days
                    except:
                        a=res['creation_date']
                        b=datetime.now()
                        c=b-a
                        d=c.days
                """except:
                    print("getaddrerrror DNE")
                    d=0"""


                

                if d>365:
                    eleventhval=1
                    aburl=1
                    var11=f"Domain age is {d} days"
                elif d<=365:
                    eleventhval=-1
                    aburl=-1
                    var11=f"Domain age working less than a year, {d} days"
        
        



                if aburl==-1:
                    twelthval=-1
                    varab="Abnormal URL detected"
                else:
                    twelthval=1 
                    varab="Website Registered on WHOIS Database"

                #print (twelthval,eleventhval,aburl,d)    
                import urllib.request, sys, re
                import xmltodict, json

                try:
                    xml = urllib.request.urlopen('http://data.alexa.com/data?cli=10&dat=s&url={}'.format(text)).read()

                    result= xmltodict.parse(xml)

                    data = json.dumps(result).replace("@","")
                    data_tojson = json.loads(data)
                    url = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["URL"]
                    rank= int(data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"])
                    #print ("rank",rank)
                    if rank<=150000:
                        thirt=1
                    else:
                        thirt=-1
                        var13=f"Ranked {rank} in Alexa Database, Larger index in alexa database detected!!"
                    #print (thirt)    
                except:
                    thirt=-1 
                    rank=-1
                    ##############var13="Larger index in alexa database"
                    var13="Not indexed in alexa database"
                    #print (rank)                  



                filename = 'phish_trainedv7mud0.001.sav'

                loaded_model = joblib.load(filename)

                arg=loaded_model.predict(([[oneval,secval,thirdval,fourthval,fifthval,seventhval,eighthval,ninthval,tenthval,eleventhval,twelthval,thirt]]))
                #print (arg[0])
                import whois
                url=text
                
                #print (res)
                #res=whois.whois(url)
                if (d!=0):
                    name=res.domain_name
                    #print (res.domain_name)
                    org=res.org
                    #print (res.org)
                    add=res.address
                    #print (res.address)
                    city=res.city
                    #print (res.city)
                    state=res.state
                    #print (res.state)
                    ziip=res.zipcode
                    #print (res.zipcode)
                    country=res.country
                    #print (res.country)
                    emails=res.emails
                    #print (res.emails)
                    dom=res.domain_name
                    #print (res.domain_name)   
                    registrar=res.registrar             
                else:
                    name="Not found in database"
                    org="Not found in database"
                    add="Not found in database"
                    city="Not found in database"
                    state="Not found in database"
                    ziip="Not found in database"
                    country="Not found in database"
                    emails="Not found in database"
                    dom="Not Found"
                    registrar="Not Found"

                
                    

                if aburl==-1 and rank==-1 :
                    arg[0]=-1
                    #phishing

                if arg[0]==1:
                    te="Legitimate"
                else:
                    te="Malicious"  
                if arg[0] == 1:
                    mal = True
                else:
                    mal = False      

                #print (name,org,add,city,state,ziip,country,emails,dom)


                from json.encoder import JSONEncoder
                final_entity = { "predicted_argument": [int(arg[0])]}
                # directly called encode method of JSON
                #print (JSONEncoder().encode(final_entity)) 
                domage=str(d)+' '+'days'
                redir=k-1

                if isinstance(cpyres.domain_name,str)==True:
                    d=cpyres.domain_name
                elif isinstance(cpyres.domain_name,list)==True:
                    d=cpyres.domain_name[0]   


                #print (d)
                try:
                    ip=socket.gethostbyname_ex(d)
                    ipadd=(ip[2][0])
                    
                    g=geocoder.ip(ipadd)
                    ipcity=g.city
                    
                    ipstate=g.state
                    
                    ipcountry=g.country
                
                    iplatitude=g.latlng[0]
                    
                    iplongitude=g.latlng[1]
                    
                except:
                    ipadd="Not Found"
                    #print (ipadd)
                    
                    ipcity="Not Found"
                    #print (city)
                    ipstate="Not Found"
                    #print (state)
                    ipcountry="Not Found"
                    #print (country)
                    iplatitude="Not Found"
                    #print (g.latlng)
                    iplongitude="Not Found"
                    #print (latitude)
                    #print (longitude)
                '''print (ipadd)
                print (ipcity)
                print (ipstate)
                print (ipcountry)
                print (iplatitude)
                print (iplongitude)
'''



                obj = Url()
                obj.result = te 
                #print (dom,rank)
                        
                tags = [name,org,state,add,city,ziip,country,emails,dom,rank,domage,varab,redir,var3,var5]

                tags = list(filter(lambda x: x!="Not Found",tags))
                tags.append(text)
                obj.link = text
                obj.add = add
                obj.state = state
                obj.city = city
                
                #obj.ziip = res['zip_code']
                obj.country = country 
                obj.emails = emails
                obj.dom = dom
                obj.org = org
                obj.rank = rank
                obj.registrar=registrar
                obj.domage=domage
                obj.varab=varab
                obj.redir=redir
                obj.var3=var3
                obj.var5=var5
                obj.ipadd=ipadd
                obj.ipcity=ipcity
                obj.ipstate=ipstate
                obj.ipcountry=ipcountry
                obj.iplatitude=iplatitude
                obj.iplongitude=iplongitude

                obj.save()
                nm=name
                oor=org
                em=emails
                #print (add)
                if add!=None:
                    if add and len (add)==1:
                        add=add.replace(",","")
                    elif len(add)>1:
                        add="".join(add)
                    #print (add)     
                
                name="".join(name)
                #print (name)
                if emails!=None:
                    emails="".join(emails)
                if org!=None:    
                    org=org.replace(",","")
                #print (org)
                '''print (dom)'''
                dom="".join(dom)
                #print (dom)
                if registrar:
                    registrar=registrar.replace(",","")
                #print (registrar)
                #print (emails)
                #print(city)
                import datetime
                import csv
                with open ('static//dataset.csv','a',encoding="utf-8") as res:        
                    writer=csv.writer(res)           
                    s="{},{},{},{},{},{},{},{},{},{},{},{},{},{}\n".format(text,te,str(name),
                        str(org).replace(",",''),
                        str(add).replace(",",''),
                        str(city).replace(",",''),
                        str(state).replace(",",''),
                        str(ziip).replace(",",''),
                        str(country).replace(",",''),str(emails).replace(",",''),
                        str(dom).replace(",",''),rank,str(registrar).replace(",",''),str(datetime.datetime.now()))
                    res.write(s)      
            
                return render(request,'result.html',{'result':'Real-time analysis successfull','f2':te,'mal': mal,'text':text,'name':nm,
                        'org':oor,
                        'add':add,
                        'city':city,
                        'state':state,
                        'ziip':ziip,
                        'country':country,'emails':em,
                        'dom':d,'rank':rank,'registrar':registrar,"tags":tags,"var13":var13,"varab":varab,"var11":var11,"var10":var10,"var5":var5,"var4":var4,"var3":var3,"ipadd":ipadd,'ipcity':ipcity,'ipstate':ipstate,'ipcountry':ipcountry,'iplatitude':iplatitude,'iplongitude':iplongitude})



        else:
            return render(request,'404.html')  
    except:
        return render(request,'404.html')  
        #website DNE or feature extraction cannot be completed
        '''return render(request,'result.html',{'result':'Real-time analysis successfull','f2':'Legtimate','mal': True,'text':text,'name':"NA",
                                'org':"NA",
                                'add':"NA",
                                'city':"NA",
                                'state':"NA",
                                'ziip':"NA",
                                'country':"NA",'emails':"NA",
                                'dom':"NA",'rank':"NA","tags":"NA","registrar":"NA","var13":"NA","varab":"NA","var11":"NA","var10":"NA","var5":"NA","var4":"NA","var3":"NA","ipadd":"NA",'ipcity':"NA",'ipstate':'NA','ipcountry':'NA','iplatitude':'NA','iplongitude':'NA'})'''
  

def api(request):
    text=request.GET['query'].lower()
    try:
        
        import datetime

        if text.startswith('https://malicious-url-detectorv5.herokuapp.com/'): 
            import datetime
            mydict = {
                "query" : text,
                "malware" : False,
                "datetime" : str(datetime.datetime.now())
            }
            response = JsonResponse(mydict)
            return response  
            

        
        elif text.startswith('https://mudv9.eu-gb.cf.appdomain.cloud/'):
            import datetime
            mydict = {
                "query" : text,
                "malware" : False,
                "datetime" : str(datetime.datetime.now())
            }
            response = JsonResponse(mydict)
            return response

        elif text.startswith('https://www.youtube.com/results?'):
            import datetime
            mydict = {
                "query" : text,
                "malware" : False,
                "datetime" : str(datetime.datetime.now())
            }
            response = JsonResponse(mydict)
            return response

        elif text.startswith('https://www.youtube.com/'):
            import datetime
            mydict = {
                "query" : text,
                "malware" : False,
                "datetime" : str(datetime.datetime.now())
            }
            response = JsonResponse(mydict)
            return response  

        elif text.startswith('https://www.google.com/search?q='):
            import datetime
            mydict = {
                "query" : text,
                "malware" : False,
                "datetime" : str(datetime.datetime.now())
            }
            response = JsonResponse(mydict)
            return response    


        #if (text.startswith('https://www.google.com/search?q=')==False) :

        else:
        
            if text.startswith('https://') or text.startswith('http://'):
                import tldextract
                do=tldextract.extract(text).domain
                sdo=tldextract.extract(text).subdomain
                suf=tldextract.extract(text).suffix

                if len(text)<=9:
                    return render(request,'errorpage.html')
                aburl=-1
                digits="0123456789"
                if text[8] in digits:
                    oneval=-1
                else:
                    oneval=1    
                if len(text)>170:
                    secval=-1
                else:
                    secval=1  
                if "@" in text:
                    thirdval=-1
                else:
                    thirdval=1    
                k=text.count("//")          
                if k>1:
                    fourthval=-1
                else:
                    fourthval=1
                    
                if "-" in do or "-" in sdo:
                    fifthval=-1
                else:
                    fifthval=1         
                if "https" in text:
                    sixthval=1
                else:
                    sixthval=-1
                temp=text
                temp=temp[6:]
                k1=temp.count("https")

                if k1 >=1:
                    seventhval=-1
                else:
                    seventhval=1
                if "about:blank" in text:
                    eighthval=-1
                else:
                    eighthval=1
                if "mail()" or "mailto:" in text:
                    ninthval=-1
                else:
                    ninthval=1
                re=text.count("//")          
                if re>3:
                    tenthval=-1
                else:
                    tenthval=1    

                import whois
                from datetime import datetime

                url=text

                d=-1
                try:
                    res=whois.whois(url)
                except:
                    #print("getaddrerrror DNE")
                    d=0
                    name="Not found in database"
                    org="Not found in database"
                    add="Not found in database"
                    city="Not found in database"
                    state="Not found in database"
                    ziip="Not found in database"
                    country="Not found in database"
                    emails="Not found in database"
                    dom="Not Found"
                if d!=0:    
                    try:
                        if len(res.creation_date)>1:
                            a=res['creation_date'][0]
                            b=datetime.now()
                            c=b-a
                            d=c.days
                    except:
                        a=res['creation_date']
                        b=datetime.now()
                        c=b-a
                        d=c.days
                """except:
                    print("getaddrerrror DNE")
                    d=0"""


                

                if d>365:
                    eleventhval=1
                    aburl=1
                elif d<=365:
                    eleventhval=-1
                    aburl=-1
                    var11="Domain age working less than a year"
        
     



                if aburl==-1:
                    twelthval=-1
                else:
                    twelthval=1                 
                import urllib.request, sys, re
                import xmltodict, json
                rank=-1
                try:
                    xml = urllib.request.urlopen('http://data.alexa.com/data?cli=10&dat=s&url={}'.format(text)).read()

                    result= xmltodict.parse(xml)

                    data = json.dumps(result).replace("@","")
                    data_tojson = json.loads(data)
                    url = data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["URL"]
                    rank= int(data_tojson["ALEXA"]["SD"][1]["POPULARITY"]["TEXT"])
                    #print ("rank",rank)
                    if rank<=150000:
                        thirt=1
                    else:
                        thirt=-1
                    #print (thirt)    
                except:
                    thirt=-1 
                    rank=-1
                    #rank="Not Indexed by Alexa"
                    #print (rank)                  




                filename = 'phish_trainedv7mud0.001.sav'

                loaded_model = joblib.load(filename)

                arg=loaded_model.predict(([[oneval,secval,thirdval,fourthval,fifthval,seventhval,eighthval,ninthval,tenthval,eleventhval,twelthval,thirt]]))
                #print (arg[0])
                import whois
                url=text
                
                #print (res)
                if (d!=0):
                    name=res.domain_name
                    #print (res.domain_name)
                    org=res.org
                    #print (res.org)
                    add=res.address
                    #print (res.address)
                    city=res.city
                    #print (res.city)
                    state=res.state
                    #print (res.state)
                    ziip=res.zipcode
                    #print (res.zipcode)
                    country=res.country
                    #print (res.country)
                    emails=res.emails
                    #print (res.emails)
                    dom=res.domain_name
                    #print (res.domain_name)                
                else:
                    name="Not found in database"
                    org="Not found in database"
                    add="Not found in database"
                    city="Not found in database"
                    state="Not found in database"
                    ziip="Not found in database"
                    country="Not found in database"
                    emails="Not found in database"
                    dom="Not Found"

                
                    

                if aburl==-1 and rank==-1 :
                    arg[0]=-1
                    #phishing

                if arg[0]==1:
                    te="Legitimate"
                else:
                    te="Malicious"  
                if arg[0] == 1:
                    mal = True
                else:
                    mal = False      


                if arg[0] == 1:
                    malstatus = False
                else:
                    malstatus = True                 
                from json.encoder import JSONEncoder
                final_entity = { "predicted_argument": [int(arg[0])]}

            import datetime
            mydict = {
                "query" : url,
                "malware" : malstatus,
                "datetime" : str(datetime.datetime.now())
            }
            response = JsonResponse(mydict)
            return response

                

    except:
        text=request.GET['query']
        import datetime
        mydict = {
            "query" : text,
            "malware" : False,
            "datetime" : str(datetime.datetime.now())
        }
        response = JsonResponse(mydict)
        return response  
        #return render(request,'404.html')       



def fetchanalysis(request):
    try:

        import warnings
        warnings.simplefilter(action='ignore', category=FutureWarning)
        import pandas as pd
        import numpy as np
        import datetime

        df=pd.read_csv("static/dataset.csv",error_bad_lines=False,warn_bad_lines=False)
        df=df.dropna()
        l=0
        m=0
        for i in df['Status']:
            if i=="Legitimate":
                l+=1
            elif i=="Malicious":
                m+=1
        unique=str(datetime.datetime.now().strftime("%Y-%m-%d-%H%M%S") )

        location1="static/"+unique+".png"
        loc1="/static/"+unique+".png"
        location2="static/"+unique+"2"+".png"
        loc2="/static/"+unique+"2"+".png"
        location3="static/"+unique+"3"+".png"
        loc3="/static/"+unique+"3"+".png"
        location4="static/"+unique+"4"+".png"
        loc4="/static/"+unique+"4"+".png"
        location5="static/"+unique+"5"+".png"
        loc5="/static/"+unique+"5"+".png"
        location6="static/"+unique+"6"+".png"
        loc6="/static/"+unique+"6"+".png"
        location7="static/"+unique+"7"+".png"
        loc7="/static/"+unique+"7"+".png"
        #print (location1,location2)

        #print (loc1,location1)
        import matplotlib.pyplot as plt
        fig, ax = plt.subplots(figsize=(5, 4), dpi=100,subplot_kw=dict(aspect="equal"))

        labels=['Legitimate','Malicious']

        sizes=[l,m]

        colors = ['yellow','orange']
        explode = (0, 0)  # explode a slice if required

        plt.pie(sizes, explode=explode, labels=labels, colors=colors,
                autopct='%1.1f%%', shadow=True)
                
        #draw a circle at the center of pie to make it look like a donut
        centre_circle = plt.Circle((0,0),0.50,color='black', fc='white',linewidth=1.25)
        fig = plt.gcf()
        fig.gca().add_artist(centre_circle)


        # Set aspect ratio to be equal so that pie is drawn as a circle.
        plt.axis('equal')
        fig.savefig(location1, dpi=100)

        from collections import Counter
        x=[]
        y=[]
        for i,j in (Counter(df['Organisation']).most_common(20)):
            if i not in ['REDACTED FOR PRIVACY','Not found in database','None','N/A']:
                x.append((i[:15]))
                y.append(j)
        #print (x,y )
        import pandas as pd
        import numpy as np
        import seaborn as sns
        import matplotlib.pyplot as plt

        sns.set_style("whitegrid", {"axes.facecolor": ".2"})

        from matplotlib.pyplot import figure
        import matplotlib.pyplot as plt

        #figure(num=None, figsize=(12,14), dpi=80, facecolor='w', edgecolor='k')
        fig, ax = plt.subplots(figsize=(20,20), facecolor='w', edgecolor='k')

        plt.bar(x, y,color='#0000ff')
        plt.xlabel('Most occuring organisations in browsing history', fontsize=32)
        plt.ylabel('Number of websites of corresponding organisation', fontsize=32)
        plt.xticks(x, x, fontsize=28, rotation=90)
        plt.yticks(fontsize=28)
        plt.title('URLs of various organisations browsed as detected from Chrome Extension',fontsize=32)
        #fig = plt.figure(1)

        ax = plt.gca()
        #ax.legend(prop={'size': 40})
        #legend = plt.legend()
        #plt.show()

        fig.savefig(location2, dpi=80,bbox_inches='tight')

        from collections import Counter
        x=[]
        y=[]
        for i,j in (Counter(df['Registrar']).most_common(20)):
            if i not in ['REDACTED FOR PRIVACY','Not found in database','None']:
                x.append(i[:20])
                y.append(j)
        #print (x,y )
        import pandas as pd
        import numpy as np
        import seaborn as sns
        import matplotlib.pyplot as plt

        sns.set_style("darkgrid", {"axes.facecolor": ".2"})

        from matplotlib.pyplot import figure
        import matplotlib.pyplot as plt

        #figure(num=None, figsize=(12,14), dpi=80, facecolor='w', edgecolor='k')
        fig, ax = plt.subplots(figsize=(20,20))

        plt.bar(x, y,color='yellow',edgecolor='black')


        plt.xlabel('Most occuring registrars in browsing history', fontsize=32)
        plt.ylabel('Number of websites of corresponding registrar', fontsize=32)
        plt.xticks(x, x, fontsize=28, rotation=90)
        plt.yticks(fontsize=28)
        plt.title('URLs of various registrars browsed as detected from Chrome Extension',fontsize=32)
        #fig = plt.figure(1)

        ax = plt.gca()
        #ax.legend(prop={'size': 40})
        #legend = plt.legend()
        #plt.show()

        fig.savefig(location3, dpi=80,bbox_inches='tight')

        from collections import Counter
        x=[]
        y=[]
        for i,j in (Counter(df['Country']).most_common(20)):
            if i not in ['REDACTED FOR PRIVACY','Not found in database','None']:
                x.append(i)
                y.append(j)
        import pandas as pd
        import numpy as np
        import seaborn as sns
        import matplotlib.pyplot as plt

        sns.set_style("darkgrid", {"axes.facecolor": ".2"})

        from matplotlib.pyplot import figure
        import matplotlib.pyplot as plt

        #figure(num=None, figsize=(12,14), dpi=80, facecolor='w', edgecolor='k')
        fig, ax = plt.subplots(figsize=(20,20))

        plt.bar(x, y,color='#0099ff',edgecolor='black')


        plt.xlabel('Most occuring country in browsing history', fontsize=32)
        plt.ylabel('Number of websites of corresponding country', fontsize=32)
        plt.xticks(x, x, fontsize=28, rotation=90)
        plt.yticks(fontsize=28)
        plt.title('URLs of various country browsed as detected from Chrome Extension',fontsize=32)
        #fig = plt.figure(1)

        ax = plt.gca()
        #ax.legend(prop={'size': 40})
        #legend = plt.legend()
        #plt.show()

        fig.savefig(location4, dpi=80,bbox_inches='tight')

        dmf=df[df['Status']=="Malicious"]
        from collections import Counter
        x=[]
        y=[]
        for i,j in (Counter(dmf['Country']).most_common(20)):
            if i not in ['REDACTED FOR PRIVACY','Not found in database','None']:
                x.append(i)
                y.append(j)
        import pandas as pd
        import numpy as np
        import seaborn as sns
        import matplotlib.pyplot as plt

        sns.set_style("darkgrid", {"axes.facecolor": ".2"})

        from matplotlib.pyplot import figure
        import matplotlib.pyplot as plt

        #figure(num=None, figsize=(12,14), dpi=80, facecolor='w', edgecolor='k')
        fig, ax = plt.subplots(figsize=(20,20))

        plt.bar(x, y,color='red',edgecolor='black')


        plt.xlabel('Most occuring country in browsing history (Malicious Website)', fontsize=32)
        plt.ylabel('Number of Malicious websites of corresponding country', fontsize=32)
        plt.xticks(x, x, fontsize=28, rotation=90)
        plt.yticks(fontsize=28)
        plt.title('Malicious URLs of various country browsed as detected from Chrome Extension',fontsize=32)
        #fig = plt.figure(1)

        ax = plt.gca()
        #ax.legend(prop={'size': 40})
        #legend = plt.legend()
        #plt.show()

        fig.savefig(location5, dpi=80,bbox_inches='tight')

        dlf=df[df['Status']=="Legitimate"]
        from collections import Counter
        x=[]
        y=[]
        for i,j in (Counter(dlf['Country']).most_common(20)):
            if i not in ['REDACTED FOR PRIVACY','Not found in database','None']:
                x.append(i)
                y.append(j)
        import pandas as pd
        import numpy as np
        import seaborn as sns
        import matplotlib.pyplot as plt

        sns.set_style("darkgrid", {"axes.facecolor": ".2"})

        from matplotlib.pyplot import figure
        import matplotlib.pyplot as plt

        #figure(num=None, figsize=(12,14), dpi=80, facecolor='w', edgecolor='k')
        fig, ax = plt.subplots(figsize=(20,20))

        plt.bar(x, y,color='#ccff33',edgecolor='black')


        plt.xlabel('Most occuring country in browsing history (Legitimate Website)', fontsize=32)
        plt.ylabel('Number of Legitimate websites of corresponding country', fontsize=32)
        plt.xticks(x, x, fontsize=28, rotation=90)
        plt.yticks(fontsize=28)
        plt.title('Legitimate URLs of various country browsed as detected from Chrome Extension',fontsize=32)
        #fig = plt.figure(1)

        ax = plt.gca()
        #ax.legend(prop={'size': 40})
        #legend = plt.legend()
        #plt.show()

        fig.savefig(location6, dpi=80,bbox_inches='tight')
        from collections import Counter
        hours=[]
        for i in df['Time']:
            hours.append(i[11:13])
            #print (i[11:13])
        
        di=dict(Counter(hours))
        di=sorted(di.items())
        

        x=[]
        y=[]
        x, y = zip(*di)
        fig, ax = plt.subplots(figsize=(20,20))

        plt.plot(x, y,color='violet', marker='o', linestyle='dashed',linewidth=5, markersize=20,label="Number of URLs browsed")#

        #plt.yticks([50,100,150,200,250,300,350,400,450,500])
        plt.xlabel('Hours in a day',fontsize=32)
        plt.ylabel('Number of URLs browsed',fontsize=32)
        plt.xticks(fontsize=28)
        plt.yticks(fontsize=28)
        plt.title("Variation in number of URLs browsed and Hours",fontsize=32)
        ax = plt.gca()
        #ax.legend(prop={'size': 20})

        #ax.tick_params(axis = 'both', which = 'major', labelsize = 15)  
        fig.savefig(location7, dpi=80,bbox_inches='tight')


                







        return render(request, 'fetchanalysis.html',{'f2':loc1,'f3':loc2,'f4':loc3,'f5':loc4,'f6':loc5,'f7':loc6,'f8':loc7})
    except:
        return render(request,'reload.html')  


        

def testresults(request):
    #return HttpResponse("about")
    return render(request, 'testresults.html')
        

def about(request):
    #return HttpResponse("about")
    try:
        return render(request, 'about.html')
    except:
        return render(request, 'about.html')
    
def geturlhistory(request):
    try:
        mydict = {
            "urls" : Url.objects.all().order_by('-created_at')
        }
        return render(request,'list.html',context=mydict)
    except:
        return render(request,'404.html')

def discuss(request):
    try:
        mydict = {
            "users" : UserFeedBack.objects.all()
        }
        return render(request,'discuss.html',context=mydict)
    except:
        return render(request,'404.html')

def search(request):
    try:
        query = request.GET['search']
        query = str(query).lower()
        mydict = {
            "urls" : Url.objects.all().filter(Q(link__contains=query) | Q(result__contains=query) | Q(created_at__contains=query) |
            Q(rank__contains=query) | Q(dom__contains=query)  | Q(country__contains=query) | Q(state__contains=query) | Q(emails__contains=query) |
            Q(add__contains=query) | Q(org__contains=query) | Q(city__contains=query)
            ).order_by('-created_at')
        }
        return render(request,'list.html',context=mydict)
    except:
        return render(request,'404.html')

def replyform(request,replyid):
    try:
        obj = UserFeedBack.objects.get(userid=replyid)
        mydict = {
        "replyid" : obj.userid,
        "title" : obj.title,
        "description" : obj.description
        }
        return render(request,'reply.html',context=mydict)
    except:
        return render(request,'404.html')

def savereply(request):
    try:
        #print("debug start")
        replyid = request.GET['replyid']
        #print(replyid)
        obj = UserFeedBack.objects.get(userid=replyid)
        obj.replied = True
        obj.reply = request.GET['userreply']
        obj.save()
        mydict = {
            "reply" : True,
            "users" : UserFeedBack.objects.all()
        }
        #print("debug end")
        return render(request,'discuss.html',context=mydict)

    except:
        return render(request,'404.html')

def searchdiscuss(request):
    try:
        query = request.GET['search']
        query = str(query).lower()
        mydict = {
            "users" : UserFeedBack.objects.all().filter(Q(title__contains=query) | Q(description__contains=query) | Q(created_at__contains=query)
            |  Q(replied__contains=query) | Q(reply__contains=query)
            )
        }
        return render(request,'discuss.html',context=mydict)
    except:
        return render(request,'404.html')

def getdataset(request):
    try:
        return render(request,'getdataset.html')
    except:
        return render(request,'404.html')
			
