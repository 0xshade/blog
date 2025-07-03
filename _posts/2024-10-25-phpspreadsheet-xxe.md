---
title: CVE-2024-45293 - XXE in PHPSpreadsheet's Excel parser
date: 2024-10-25 00:00:00 +0400
categories: [Security, Research]
tags: [vulnerability, xxe, php, cve, security-research]
---

## Overview

![XXE Cover Image](/assets/posts/phpspreadsheet/cover.png)

The PHPSpreadSheet library, part of the widely used PHPOffice open-source suite, was discovered to be vulnerable to XML External Entity (XXE) Injection. This vulnerability arises from improperly defined XXE sanitization filters within the XLSX reader, allowing for the parsing of user-supplied Excel spreadsheets.

Exploitation involves supplying a crafted Excel spreadsheet (XLSX) with an embedded XML file containing a payload. When processed, this payload can reveal sensitive files on servers running applications that depend on this library.

Although a fix for a similar XXE vulnerability was introduced in version 2.2.1, it was not sufficiently robust. This blog presents a bypass for the existing patch and explores the associated impacts.

Affected Versions include:

    >= 2.2.0, < 2.3.0
    < 1.29.1
    >= 2.0.0, < 2.1.1

Since PHPSpreadsheet is the successor for the now unmaintained PHPExcel and is widely adopted, This vulnerability affects a range of applications that are utilizing one of the core features of the library.

The Shaheen research team reported the vulnerability in August, which was later fixed and assigned CVE-2024-45293 in September 13th, 2024.

## Full Research Details

I've covered the technical analysis, proof-of-concept, and detailed exploitation techniques, in the Shaheen blog below:

**[CVE-2024-45293: XXE in PHPSpreadsheet's Excel parser](https://shaheen.beaconred.net/research/2024/10/25/phpspreadsheet-xxe.html)**