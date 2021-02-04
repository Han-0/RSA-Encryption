# RSA-Encryption
Basic example of an RSA exchange implemented in JAVA

Dependencies: JDK 11 or greater.

Usage: 

0. Open directory in a CLI or IDE
1. Execute KeyGen.java
```
  java KeyGen.java
```
2. Import a message file to the same directory as Sender.java (can be a file of any type).
3. Execute Sender.java
```
  java Sender.java
```
4. Execute Reciever.java
```
  java Receiver.java
```
5. If you want the decoded file to be in readable format, give it the original file extension when prompted for a file name in Reciever.java.

Known Issues:

Decryption algorithm produces more bytes than were present in original file.
