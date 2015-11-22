#!/usr/bin/python3
# -*- coding: utf-8 -*-
from datetime import datetime
import numpy as np
import matplotlib.pyplot as plt
from sklearn import svm, datasets
from lxml import etree
from io import StringIO, BytesIO
from collections import Counter

parser = etree.XMLParser(ns_clean=True, recover=True)
tree   = etree.parse('jun14-p1.xml', parser)
root = tree.getroot()

ipdict = dict()

traits = np.array([[0, 0]])
classification = np.array([[1]])
for child in root:
    if child.find('appName').text == "HTTPWeb" and (child.find('destination').text[:len('192.168.5.')] == '192.168.5.'):
        source = child.find('source').text
        dest = child.find('destination').text
        is_malicious = child.find('Tag').text == 'Attack'
        start = child.find('startDateTime').text
        end = child.find('stopDateTime').text
        start_date = datetime.strptime(start, '%Y-%m-%dT%H:%M:%S')
        end_date = datetime.strptime(end, '%Y-%m-%dT%H:%M:%S')
        duration = (end_date - start_date).total_seconds()
        total_bytes = int(child.find('totalSourceBytes').text) + int(child.find('totalDestinationBytes').text)
        #if source not in ipdict:
        #    ipdict[source] = dict()
        #    ipdict[source]['duration'] = 0
        #    ipdict[source]['total_bytes'] = 0
        #    ipdict[source]['count'] = 0
        malicious = 1 if is_malicious else 0
        #print(is_malicious)
        #ipdict[source]['duration'] += duration
        #ipdict[source]['total_bytes'] += total_bytes
        #ipdict[source]['count'] += 1
        traits = np.append(traits, [[duration, total_bytes/1024]], axis=0)
        classification = np.append(classification, [malicious])


print(traits)
print(classification)
#print(ipdict.keys())
#for source in ipdict.values():
#    print(source)

h = 1.0  # step size in the mesh

C = 1.0  # SVM regularization parameter

x_min, x_max = traits[:, 0].min() - 1, traits[:, 0].max() + 1
print(x_min, x_max)
y_min, y_max = traits[:, 1].min() - 1, traits[:, 1].max() + 1
print(y_min, y_max)
xx, yy = np.meshgrid(np.arange(x_min, x_max, h), np.arange(y_min, y_max, h))
print(xx, yy)

print("fitting svm")
#clf = svm.SVC(kernel='linear', C=C).fit(traits, classification)
clf = svm.SVC(kernel='rbf', gamma=0.3, C=C).fit(traits, classification)
#clf = svm.SVC(kernel='poly', degree=3, C=C).fit(traits, classification)
print("predicting")
Z = clf.predict(np.c_[xx.ravel(), yy.ravel()])

## Put the result into a color plot
print("reshaping")
Z = Z.reshape(xx.shape)

print("drawing")
plt.title("Malicious?")
plt.contourf(xx, yy, Z, cmap=plt.cm.Paired, alpha=0.8)
plt.xlabel('duration of connection')
plt.ylabel('bytes transfered (kb)')
plt.xlim(xx.min(), xx.max())
plt.ylim(yy.min(), yy.max())
plt.xticks(())
plt.yticks(())

b = plt.scatter(traits[:, 0], traits[:, 1], c=classification, cmap=plt.cm.Paired)

plt.show()
