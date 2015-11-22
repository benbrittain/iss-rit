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
tree   = etree.parse('jun17-p2.xml', parser)
root = tree.getroot()

ipdict = Counter()

traits = np.array([[0, 0]])
classification = np.array([[1]])
for child in root:
    if child.find('appName').text == "SSH":
        source = child.find('source').text
        dest = child.find('destination').text
        is_malicious = child.find('Tag').text == 'Attack'
        start = child.find('startDateTime').text
        end = child.find('stopDateTime').text
        start_date = datetime.strptime(start, '%Y-%m-%dT%H:%M:%S')
        end_date = datetime.strptime(end, '%Y-%m-%dT%H:%M:%S')
        duration = (end_date - start_date).total_seconds()
        total_bytes = int(child.find('totalSourceBytes').text) + int(child.find('totalDestinationBytes').text)
        ipdict[source] += 1
        traits = np.append(traits, [[duration, ipdict[source]]], axis=0)
        if is_malicious:
            classification = np.append(classification, [1])
        else:
            classification = np.append(classification, [0])

h = .02  # step size in the mesh

print(len(classification))
print(len(traits))
C = 1.0  # SVM regularization parameter
svc = svm.SVC(kernel='linear', C=C).fit(traits, classification)
print("doing an svm")
#rbf_svc = svm.SVC(kernel='rbf', gamma=0.7, C=C).fit(traits, classification)
#print("doing an svm")
#poly_svc = svm.SVC(kernel='poly', degree=3, C=C).fit(traits, classification)
#print("doing an svm")
#lin_svc = svm.LinearSVC(C=C).fit(traits, classification)
#print("doing an svm")

# create a mesh to plot in
x_min, x_max = traits[:, 0].min() - 1, traits[:, 0].max() + 1
y_min, y_max = traits[:, 1].min() - 1, traits[:, 1].max() + 1
xx, yy = np.meshgrid(np.arange(x_min, x_max, h), np.arange(y_min, y_max, h))

# title for the plots
titles = ['SVC with linear kernel',
        'LinearSVC (linear kernel)',
        'SVC with RBF kernel',
        'SVC with polynomial (degree 3) kernel']

for i, clf in enumerate((svc, svc)):
    # Plot the decision boundary. For that, we will assign a color to each
    # point in the mesh [x_min, m_max]x[y_min, y_max].
    plt.subplot(2, 2, i + 1)
    plt.subplots_adjust(wspace=0.4, hspace=0.4)

    Z = clf.predict(np.c_[xx.ravel(), yy.ravel()])

    # Put the result into a color plot
    Z = Z.reshape(xx.shape)
    plt.contourf(xx, yy, Z, cmap=plt.cm.Paired, alpha=0.8)

    # Plot also the training points
    plt.scatter(traits[:, 0], traits[:, 1], c=classification, cmap=plt.cm.Paired)
    plt.xlabel('duration of connection')
    plt.ylabel('connection count')
    plt.xlim(xx.min(), xx.max())
    plt.ylim(yy.min(), yy.max())
    plt.xticks(())
    plt.yticks(())
    plt.title(titles[i])

plt.show()
