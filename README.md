# Simple send-receive app

This application was build as a project for the Computer and Communication Networks course at Faculty of Informatics and Information Technologies at STU in Bratislava.

It works by sending packets with custom protocol build on top of the UDP protocol and adds the reliability and connection handling (similarly to the TCP protocol).

The program can run in two modes:
* sender mode, sending data
* receiver mode, receiving data

Initially for two nodes to connect, one must be receiver and the other must be sender. After they connect, each can send a signal to initiate the switching of roles (sender becomes receiver and vice-versa).

This app is able to send both textual messages (plain text in UTF-8 format) and all types of files (.xlsx, .txt, .py, .c, .ipynb, etc.).