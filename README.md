# Malicious-URL-Detector

[![Concept Video](https://img.youtube.com/vi/-6fd996HWrQ/0.jpg)](https://www.youtube.com/watch?v=-6fd996HWrQ)


** YouTube demo link : https://youtu.be/-6fd996HWrQ

1. This application is live at : https://mudvfinalradar.eu-gb.cf.appdomain.cloud/

2. Live Data Analysis Portal : https://mudvfinalradar.eu-gb.cf.appdomain.cloud/fetchanalysis

3. Chrome Extension repository : https://github.com/abhisheksaxena1998/ChromeExtension-Malicious-URL-v5-IBM

4. Dataset link : https://github.com/Hritiksum/MUD_dataset

5. Training and Testing link : https://github.com/Hritiksum/MUD_dataset/blob/master/Training%20and%20Testing%20Model/Training%20and%20Testing.ipynb

Life is dependent mainly on internet in todays life for moving business online, or making online transactions. Resulting in cyber-thefts and cyber-frauds increasing exponentially day by day, leading to compromised security and infiltration of hackers or third parties while transacting online.
*******
## Notable Results: Twitter Bitcoin Scam (Detected successfully by our Data Science/Machine Learning solution – Malicious URL Detector.)

On July 15, 2020, between 20:00 and 22:00 UTC, around 130 high-profile Twitter accounts were compromised by outside parties to promote a bitcoin scam. Twitter and other media sources confirmed that the perpetrators had gained access to Twitter's administrative tools so that they could alter the accounts themselves and post the tweets directly. They appeared to have used social engineering to gain access to the tools via Twitter employees.

Compromised accounts included those of well-known individuals such as <strong>Barack Obama, Joe Biden, Bill Gates, Jeff Bezos, MrBeast, Michael Bloomberg, Warren Buffett, Floyd Mayweather, Kim Kardashian, and Kanye West; and companies such as Apple, Uber, and Cash App</strong>.
*******
### Link to implemented detailed Case Study: https://mudvfinalradar.eu-gb.cf.appdomain.cloud/casestudy
*******
# Test Data

Test URL | Result (Target)
------------ | -------------
https://home-paypal-jp.moonkahonda.com/panel_JP/-/jp/xppl/ | Malicious
https://galsterberg.panomax.com/ | Legitimate
https://oberstdorf.panomax.com/schrattenwang | Legitimate
https://addons.mozilla.org/de/firefox/addon/mynthos-tv/?src=search | Legitimate
http://ord-amazsn.com | Malicious
http://ww17.login-appleid.apple.com.alert-wode.com/ | Malicious
http://support.facebook.com-uuynqiyacp.tekhencorp.com/ | Malicious
https://galsterberg.panomax.com/ | Legitimate
https://www.google.com/ | Legitimate
https://wallpapersite.com/abstract/ | Legitimate
https://www.freepik.com/free-vector | Legitimate

## This project is deployed on IBM Cloud Foundry

### Link to Malicious URL Detector Anti-Phishing solution:
https://mudvfinalradar.eu-gb.cf.appdomain.cloud/

    Note : While using Malicious URL Detector web application on a browser protected by Malicious URL Detector browser extension, the web application might take sometime to load, as the REST API endpoint is called through JavaScript in Chrome Extension and at this instant Cloudant database is updated too, since we are using LITE plan of Cloudant Database there are limited writes available. If these requests exceed number of writes availabe for robust functioning of application these are queued, which leads to slowness. 

1.	Type a valid URL for example to fetch analysis:
    
    https://www2.deloitte.com/in/en.html
    
    ![How to install](/Images/img9.png)
    
    ![How to install](/Images/img91.png)
    
    ![How to install](/Images/img92.png)
    
    
2.	Another example of Legitimate URL

    https://technoutsav.techgig.com/
    
    ![How to install](/Images/img8.png)
    
    ![How to install](/Images/img81.png)
    
    ![How to install](/Images/img82.png)
    
3.	Another Legitimate URL

    https://www.mi.com

    This is an example of Legitimate URL.
    
    ![How to install](/Images/img7.png)
    
    ![How to install](/Images/img71.png)
    
    ![How to install](/Images/img72.png)
    
4.	Example of Malicious Website

    https://promo-twitter.info
    
    ![How to install](/Images/img10.png)
    
    ![How to install](/Images/img101.png)
    
    ![How to install](/Images/img102.png)
    
5.	Another Malicious URL

    https://home-paypal-jp.moonkahonda.com/panel_JP/-/jp/xppl/
    
    ![How to install](/Images/img11.png)
    
    ![How to install](/Images/img111.png)
    
    ![How to install](/Images/img112.png)

## Installation Guide

1.	Extract Malicious-Urlv5 zip file.
2.	Inside Malicious-Urlv5 there is a file requirements.txt
3.	Open command prompt in Malicious-Urlv5 folder

    ![How to install](/Images/img1.png)

4.  Type following command in cmd

    ![How to install](/Images/img2.png)
    
5.  Dependencies will start installing.  

    ![How to install](/Images/img3.png)
    ![How to install](/Images/img4.png)

6.	To run the code, write following command in terminal.

    python manage.py runserver
    
    ![How to install](/Images/img5.png)
    
7.	Type http://127.0.0.1:8000/ in URL bar of browser and press Enter. Machine Learning powered Web                 Application will start.    

    ![How to install](/Images/img6.png)
    
