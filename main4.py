#!/usr/bin/env python
# -*- coding: utf-8 -*-

from PyQt5.QtWidgets import QWidget
from PyQt5.QtWidgets import QLabel
from PyQt5.QtWidgets import QCheckBox
from PyQt5.QtWidgets import QGroupBox
from PyQt5.QtWidgets import QScrollArea
from PyQt5 import QtGui

from PyQt5.QtWidgets import QApplication
from PyQt5.QtWidgets import QHBoxLayout, QVBoxLayout, QGridLayout

import sys

newfont = QtGui.QFont("Inconsolata", 10)
# lst = [u"D", u"E", u"EF", u"F", u"FG", u"G", u"H", u"JS", u"J", u"K", u"M", u"P", u"R", u"S", u"T", u"U", u"V", u"X", u"Y", u"Z"]
lst2 = []

'''
# Label Set
strbase = "strbase"
linecount = 0
textcount = 50
# newfont = QtGui.QFont("Times", 8, QtGui.QFont.Bold)
newfont = QtGui.QFont("Inconsolata", 10)
'''

with open('rain.py-20180623', 'r+') as x:
    for y in x:
        '''z = str(strbase + str(linecount))
        z = QtWidgets.QLabel(w)
        z.setFont(newfont)
        z.setText(y)
        z.move(50, textcount)
        linecount += 1
        textcount += 16'''
        lst2.append(y)

class MyApp(QWidget):
    def __init__(self):
        super(MyApp, self).__init__()
        window_width = 1600
        window_height = 900
        self.setFixedSize(window_width, window_height)
        self.initUI()

    def createLayout_group(self, number):
        sgroupbox = QGroupBox("LOG File: {}:".format(number), self)
        layout_groupbox = QVBoxLayout(sgroupbox)
        for i in range(len(lst2)):
            # item = QCheckBox(lst2[i], sgroupbox)
            item = QLabel(lst2[i], sgroupbox)
            item.setFont(newfont)
            sgroupbox.setFont(newfont)
            item.setMaximumHeight(10)
            item.setMinimumHeight(10)
            #sgroupbox.setMaximumHeight(12)
            #sgroupbox.setMinimumHeight(12)
            p = item.palette()
            p2 = sgroupbox.palette()
            item.setAutoFillBackground(True)
            sgroupbox.setAutoFillBackground(True)
            p2.setColor(sgroupbox.backgroundRole(), QtGui.QColor("#202020"))
            p.setColor(item.backgroundRole(), QtGui.QColor("#202020"))
            # p.setColor(QtGui.QPalette.Text, QtGui.QColor("#ffffff"))
            sgroupbox.setStyleSheet('QGroupBox {color: #32CD32;}')
            item.setStyleSheet('QLabel {color: #ffcc00;}')
            sgroupbox.setPalette(p2)
            item.setPalette(p)
            layout_groupbox.addWidget(item)
        layout_groupbox.addStretch(1)
        return sgroupbox

    def createLayout_Container(self):
        self.scrollarea = QScrollArea(self)
        self.scrollarea.setFixedWidth(1600)
        self.scrollarea.setWidgetResizable(True)

        widget = QWidget()
        self.scrollarea.setWidget(widget)
        self.layout_SArea = QVBoxLayout(widget)

        for i in range(3):
            self.layout_SArea.addWidget(self.createLayout_group(i))
        self.layout_SArea.addStretch(1)

    def initUI(self):
        self.createLayout_Container()
        self.layout_All = QVBoxLayout(self)
        self.layout_All.addWidget(self.scrollarea)
        self.show()

def main():
    app = QApplication(sys.argv)
    window = MyApp()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
