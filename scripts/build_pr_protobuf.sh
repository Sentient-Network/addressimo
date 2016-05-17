#!/bin/bash
PR_DIR=../addressimo/paymentprotocol
protoc -I=$PR_DIR --python_out=$PR_DIR $PR_DIR/paymentrequest.proto