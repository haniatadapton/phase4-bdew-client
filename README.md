# phase4-bdew-client

A Java-based AS4 client implementation for BDEW (German Association of Energy and Water Industries) message exchange using the phase4 library.

## Overview

This project provides a client implementation for sending AS4 messages according to the BDEW profile specifications. It uses the phase4 library for AS4 message handling and supports secure message exchange with encryption and digital signatures.

## Prerequisites

- Java 17 or later
- Maven 3.6 or later
- Valid PKCS12 keystores for:
  - Sender certificate (ks1.p12)
  - Trust store (truststore.p12)

## Configuration

### Keystore Setup

Place your keystore files in the project root:
- `ks1.p12` - Sender's keystore
- `truststore.p12` - Trust store containing receiver certificates

Default credentials (customize in application.properties):
- Keystore password: `changeit`
- Key alias: `cert1`

### Application Properties

The main configuration is in `src/test/resources/application.properties`. Key settings include:

To send a message run the file src/test/java/com/helger/phase4/bdew/MainPhase4BDEWSenderExample.java

There you can also edit the receiver URL. To implement the key exchange the file src/main/java/com/helger/phase4/bdew/Phase4BDEWSender.java needs to be edited.
