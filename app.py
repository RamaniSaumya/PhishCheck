# import os
import pandas as pd
import numpy as np
# import tensorflow as tf
import whois
from datetime import datetime
from urllib.error import URLError
# import socket
# import ssl
from urllib.parse import urlparse,urlencode
import ipaddress
import re
import pickle

from xgboost import XGBClassifier
# from tensorflow.keras.models import load_model 


from flask import Flask, render_template, request

with open("xgb_model.pkl", "rb") as model_file:
    model = pickle.load(model_file) 

# print(dir(model)) 


# model = load_model("cnn.h5")
# print(type(model))  # Check the type

app = Flask(__name__)

def check_domain_registration(url):
    try:
        # Remove http:// or https:// if present
        domain = url.replace("http://", "").replace("https://", "").split('/')[0]

        # Try to get domain information
        domain_info = whois.whois(domain)

        if domain_info.domain_name:
            # print("Domain is registered")
            # print(f"Registration Date: {domain_info.creation_date}")
            # print(f"Expiry Date: {domain_info.expiration_date}")
            return 0
    except Exception as e:
        # print(f"Domain is not registered or an error occurred: {e}")
        return 1

def domainAge(domain_name):
    try:
        domain_info = whois.whois(domain_name)
    except Exception as e:
        print(f"Error fetching WHOIS data: {e}")
        return 1  # Assume suspicious if WHOIS lookup fails

    creation_date = domain_info.creation_date
    expiration_date = domain_info.expiration_date

    # Handle cases where WHOIS data is not available
    if creation_date is None or expiration_date is None:
        return 1

    # Handle cases where WHOIS returns lists
    if isinstance(creation_date, list):
        creation_date = creation_date[0]
    if isinstance(expiration_date, list):
        expiration_date = expiration_date[0]

    # Ensure datetime format
    if isinstance(creation_date, str):
        try:
            creation_date = datetime.strptime(creation_date, "%Y-%m-%d")
        except ValueError:
            return 1
    if isinstance(expiration_date, str):
        try:
            expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
        except ValueError:
            return 1

    # Calculate domain age (from creation date to today)
    ageofdomain = (datetime.now() - creation_date).days

    # If the domain age is less than 6 months, return 1 (potentially suspicious)
    return 1 if (ageofdomain / 30) < 6 else 0



def domainEnd(domain_name):
    try:
        if domain_name is None:
            return 1

        expiration_date = domain_name.expiration_date
        if expiration_date is None:
            return 1

        # Handle case where expiration_date is a list
        if isinstance(expiration_date, list):
            expiration_date = expiration_date[0]

        if isinstance(expiration_date, str):
            try:
                expiration_date = datetime.strptime(expiration_date, "%Y-%m-%d")
            except:
                return 1

        today = datetime.now()
        end = abs((expiration_date - today).days)
        if ((end/30) < 6):
            return 0
        return 1

    except:
        return 1
    

    # Domain of URL
def getDomain(url):
  domain = urlparse(url).netloc
  if re.match(r"^www.",domain):
    domain = domain.replace("www.","")
  return domain


# IP Address in URL
def hasIP(url):
  try:
    ipaddress.ip_address(url)
    ip=1 # means ip is present in url -> It's phished
  except:
    ip=0 # means ip is not present in url -> It's Legitimate
  return ip


def hasSym(url):
    if "@" in url:
        temp = 1  # URL has '@' symbol -> It's phished
    else:
        temp = 0  # URL does not have '@' symbol -> It's Legitimate
    return temp



# Length of URL
def getLen(url):
  if(len(url) < 54):
    temp=0 # It's legitimate
  else:
    temp=1 # Len is increased to hide doubtful part , It's Phished
  return temp


# Depth of URL (To get the no of '/')
def getDepth(url):
  s = urlparse(url).path.split('/')
  ct = 0
  for i in range(len(s)):
    if(len(s[i])!=0):
      ct=ct+1
  return ct


# Redirection in URL ("//" must be present below 6th position)
def redirect(url):
    pos = url.rfind('//')
    return 1 if pos > 7 else 0


# HTTP/HTTPs in URL
def checkHTTP(url):
  domain = urlparse(url).netloc
  if 'https' in domain:
    return 1 # It's phished one
  else:
    return 0 # It's Legitimate one
  

# URL Shortening
shortening_services = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "shorte.st", "clk.sh", "x.co", "tr.im", "goo.su"
]

def urlShortened(url):
    domain = urlparse(url).netloc
    return 1 if domain in shortening_services else 0 # 1 -> Phished one or 0 -> Legitimate one

# "-" in Domain
def checkPrefSuff(url):
  domain = urlparse(url).netloc
  if '-' in domain:
    return 1 # Phished one
  else:
    return 0 # Legitimate one
  
# IFrame Redirection
# If the iframe is empty or repsonse is not found then, the value assigned to this feature is 1 (phishing)
# or else 0 (legitimate).
def iframe(response):
  if response == "":
      return 1
  else:
      if re.findall(r"[|]", response.text):
          return 0
      else:
          return 1
      

# Status Bar Customization
def mouseOver(response):
  if response == "" :
    return 1
  else:
    if re.findall("", response.text):
      return 1
    else:
      return 0
    

# Disable Right Click
def rightClick(response):
  if response == "":
    return 1
  else:
    if re.findall(r"event.button ?== ?2", response.text):
      return 0
    else:
      return 1
    
# Website Forwarding
# Taking assumption of visiting Legitimate site max one time
def forwarding(response):
  if response == "":
    return 1
  else:
    if len(response.history) <= 2:
      return 0
    else:
      return 1
    

def featureExtraction(url):
    features = []
    # Initialize domain_name first
    dns = 0
    try:
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url
        domain_name = whois.whois(urlparse(url).netloc)
    except:
        dns = 1
        domain_name = None

    #Address bar based features (10)
    # features.append(getDomain(url))
    features.append(hasIP(url))
    features.append(hasSym(url))
    features.append(getLen(url))
    features.append(getDepth(url))
    features.append(redirect(url))
    features.append(checkHTTP(url))
    features.append(urlShortened(url))
    features.append(checkPrefSuff(url))
    features.append(check_domain_registration(url))
    features.append(domainAge(domain_name))
    features.append(domainEnd(domain_name))

    # HTML & Javascript based features
    try:
        response = requests.get(url)
    except:
        response = ""
    features.append(iframe(response))
    features.append(mouseOver(response))
    features.append(rightClick(response))
    features.append(forwarding(response))

    return features





def features_df(features_combined):
    feature_names = ['Have_IP', 'Have_At', 'URL_Length', 'URL_Depth','Redirection',
                 'https_Domain', 'TinyURL', 'Prefix/Suffix', 'DNS_Record',
                 'Domain_Age', 'Domain_End', 'iFrame', 'Mouse_Over',
                 'Right_Click', 'Web_Forwards']


    final_df = pd.DataFrame([features_combined], columns=feature_names)
    
    # Convert object type columns to numerical values
    for col in final_df.select_dtypes(include=['object']).columns:
        final_df[col] = 1  # Assign 1 to all object-type values
    
    return final_df

# import pandas as pd

def predict_model(final):
    final = pd.get_dummies(final, drop_first=True)


    prediction = model.predict(final)
    return prediction
    # print(prediction)


@app.route('/')
def home():
    return render_template('index.html')

@app.route('/predict', methods=['POST'])
def predict():
    url = request.form['url']  # Get the URL input from the form
    features_rec=[]
    features_rec2=[]
    features_rec=featureExtraction(url)
    features_rec=features_df(features_rec)
    print(features_rec)
    result=predict_model(features_rec)
    print(features_rec)
    return f"{features_rec}"
    # return render_template('index2.html')

if __name__ == "__main__":
    app.run(debug=True)
